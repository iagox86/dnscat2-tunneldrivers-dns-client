mod dns_error;

use std::default::Default;
use std::error;
use std::io;
use std::net;
use trust_dns::rr::rdata::txt;
use trust_dns::rr::RecordType;
use trust_dns::rr::domain::{Label, Name};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

pub enum NameIdentifier {
  Domain(Name),
  Tag(Name),
}

pub enum NameEncoder {
  Hex,
  Base32,
  // TODO: Implement an encoder/decoder on this
}

impl NameEncoder {
  fn decode(&self, s: &str) -> dns_error::Result<Vec<u8>> {
    match *self {
      NameEncoder::Hex => Ok(hex::decode(s)?),
      NameEncoder::Base32 => match base32::decode(base32::Alphabet::RFC4648 { padding: false }, s) {
        Some(s) => Ok(s),
        None    => Err(dns_error::Error::encoding_error(String::from("Error decoding from base32"))),
      }
    }
  }
}

pub struct Settings {
  name_identifier: NameIdentifier,
  name_encoder:    NameEncoder,
  segment_length:  u16,
  record_type:     RecordType,
}

impl Default for Settings {
  fn default() -> Settings {
    Settings {
      name_identifier: NameIdentifier::Tag(Name::from_ascii("dnscat2").unwrap()),
      name_encoder:    NameEncoder::Hex,
      segment_length:  63,
      record_type:     RecordType::A,
    }
  }
}

fn encode_name(data: &[u8], settings: &Settings) -> dns_error::Result<Name> {
  let mut name = Name::new();

  // Add a tag if that's what we're doing
  if let NameIdentifier::Tag(tag) = &settings.name_identifier {
    name = name.append_domain(tag);
  }

  // Encode data
  let data = match settings.name_encoder {
    NameEncoder::Hex => hex::encode(data),
    NameEncoder::Base32 => base32::encode(base32::Alphabet::RFC4648 { padding: false }, data).to_lowercase(),
  };

  for c in data.as_bytes().chunks(settings.segment_length as usize) {
    let label = Label::from_raw_bytes(c)?;
    name = name.append_label(label)?;
  }

  // Add a domain if that's what we're doing
  if let NameIdentifier::Domain(domain) = &settings.name_identifier {
    name = name.append_domain(domain);
  }

  Ok(name)
}

fn decode_a(addresses: Vec<&net::Ipv4Addr>) -> dns_error::Result<Vec<u8>> {
  // Handle no data
  if addresses.len() == 0 {
    return Err(dns_error::Error::bad_data(String::from("Zero addresses returned")));
  }

  // Convert all the addresses to u8[4]
  let mut addresses: Vec<[u8; 4]> = addresses
    .into_iter()
    .map(|a| a.octets())
    .collect();

  // Sort them by the first field
  addresses.sort_by(|a, b| a[0].cmp(&b[0]));

  // Trim off the first value and merge them all together
  let mut result: Vec<u8> = Vec::new();
  for address in addresses {
    result.extend_from_slice(&address[1..]);
  }

  // Grab the first byte, which is the length
  let len_from_buffer: usize = result.remove(0) as usize;

  // Make sure the length is sane
  if result.len() < len_from_buffer {
    return Err(dns_error::Error::bad_data(format!("Invalid length value! First byte was {}, results were {}", len_from_buffer, result.len())));
  }

  // Truncate to that length
  result.truncate(len_from_buffer);

  // Done!
  Ok(result)
}

fn decode_aaaa(addresses: Vec<&net::Ipv6Addr>) -> dns_error::Result<Vec<u8>> {
  if addresses.len() == 0 {
    return Err(dns_error::Error::bad_data(String::from("Zero addresses returned")));
  }

  // Convert all the addresses to u8[4]
  let mut addresses: Vec<[u8; 16]> = addresses
    .into_iter()
    .map(|a| a.octets())
    .collect();

  // Sort them by the first field
  addresses.sort_by(|a, b| a[0].cmp(&b[0]));

  // Trim off the first value and merge them all together
  let mut result: Vec<u8> = Vec::new();
  for address in addresses {
    result.extend_from_slice(&address[1..]);
  }

  // Grab the first byte, which is the length
  let len_from_buffer: usize = result.remove(0) as usize;

  // Make sure the length is sane
  if result.len() < len_from_buffer {
    return Err(dns_error::Error::bad_data(format!("Invalid length value! First byte was {}, results were {}", len_from_buffer, result.len())));
  }

  // Truncate to that length
  result.truncate(len_from_buffer);

  // Done!
  Ok(result)
}

fn decode_txt(data: Vec<&txt::TXT>, settings: &Settings) -> dns_error::Result<Vec<u8>> {
  // Make sure we have exactly one record
  if data.len() != 1 {
    return Err(dns_error::Error::bad_data(format!("An unexpected number of TXT records ({}) were returned!", data.len())));
  }

  // Pull out the single record
  let data = data[0].txt_data();

  // Again, there should be exactly one record
  if data.len() != 1 {
    return Err(dns_error::Error::bad_data(format!("An unexpected number of TXT entries ({}) were returned!", data.len())));
  }

  // Again, pull out the single record
  let data = match data.get(0) {
    Some(s) => s,
    None => return Err(dns_error::Error::bad_data(String::from("No text record was found"))),
  };

  let s = std::str::from_utf8(&data)?;
  return settings.name_encoder.decode(s);
}

/*fn decode_mx(name: &Name, settings: &Settings) -> Result<Vec<u8>, Box<error::Error>> {
  println!("Name: {:?}", name);
  let name = name.to_utf8();
  println!("Name (utf-8): {:?}", name);
  return Ok(vec![]);
} */

fn default_socket_addr() -> net::SocketAddr {
  "8.8.8.8:53".parse().unwrap()
}

fn get_socket_addr(host: Option<&str>) -> Result<net::SocketAddr, Box<error::Error>> {
  match host {
    Some(host) => Ok(host.parse::<net::SocketAddr>()?),
    _          => Ok(default_socket_addr()),
  }
}

fn main() {
  let socket_addr = get_socket_addr(Some("127.0.0.1:53535")).expect("Invalid DNS server given1");

  let name_server = NameServerConfig {
    socket_addr: socket_addr,
    protocol: Protocol::Udp,
    tls_dns_name: None
  };

  let mut resolver_config = ResolverConfig::new();
  resolver_config.add_name_server(name_server);

  // Construct a new Resolver with default configuration options
  let mut resolver_opts = ResolverOpts::default();
  resolver_opts.cache_size = 0;

  let resolver = Resolver::new(resolver_config, resolver_opts).unwrap();

  // TODO: Don't hardcode the record type
  let settings = Settings {
    record_type: RecordType::TXT,
    name_identifier: NameIdentifier::Tag(Name::from_ascii("a").unwrap()),
    //name_encoder: NameEncoder::Base32,
    ..Default::default()
  };

  // TODO: Use system resolver
  //let mut resolver = Resolver::from_system_conf().unwrap();

  println!("Ready to roll! Just type something!");
  loop {
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    let s = encode_name(s.as_bytes(), &settings).unwrap().to_ascii();

  // Lookup the IP addresses associated with a name.
    println!("Sending: {:?}", s);

    // TODO: Handle errors
    let response = match settings.record_type {
      RecordType::A => {
        match decode_a(resolver.ipv4_lookup(&s[..]).unwrap().iter().collect()) {
          Ok(s) => Some(s),
          _ => None,
        }
      },
      RecordType::AAAA => {
        match decode_aaaa(resolver.ipv6_lookup(&s[..]).unwrap().iter().collect()) {
          Ok(s) => Some(s),
          _ => None,
        }
      },
      RecordType::TXT => {
        match decode_txt(resolver.txt_lookup(&s[..]).unwrap().iter().collect(), &settings) {
          Ok(s) => Some(s),
          _ => None,
        }
      }, /*
      RecordType::MX => {
        if let Some(result) = resolver.mx_lookup(&s[..]).unwrap().iter().next() {
          let result = decode_mx(result.exchange(), &settings);
          println!("{:?}", result);
          None
        } else {
          None
        }
      } */
      _ => {
        None
      }
    };

    match response {
      Some(r) => println!("response: {:?}", String::from_utf8(r)),
      _ => println!("no response!"),
    }
}

  // There can be many addresses associated with the name,
  //  this can return IPv4 and/or IPv6 addresses
//  let address = response.next().expect("no addresses returned!");
//
//  if address.is_ipv4() {
//      assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//  } else {
//      assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
//  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_get_socket_addr() {
    // Parse a good address
    assert_eq!(
      get_socket_addr(Some("127.0.0.1:53")).unwrap(),
      net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)), 53)
    );

    // Parse another address to make sure I didn't hardcode something by mistake
    assert_eq!(
      get_socket_addr(Some("1.2.3.4:1234")).unwrap(),
      net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::new(1, 2, 3, 4)), 1234)
    );

    // Parse some invalid addresses
    assert!(get_socket_addr(Some("1.2.3.4")).is_err());
    assert!(get_socket_addr(Some("1.2.3.4:")).is_err());
    assert!(get_socket_addr(Some("1.2.3:4")).is_err());

    // Use the default address
    assert_eq!(
      get_socket_addr(None).unwrap(),
      net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::new(8, 8, 8, 8)), 53)
    )
  }

  fn ip(ip: &str) -> net::Ipv4Addr {
    return ip.parse().unwrap();
  }

  fn ip6(ip: &str) -> net::Ipv6Addr {
    return ip.parse().unwrap();
  }

  fn fromto(start: u8, end: u8) -> Vec<u8> {
    return (start..end+1).collect();
  }

  #[test]
  fn test_decode_a() {
    // Increasingly longer, but otherwise normal, addresses
    assert_eq!(decode_a(vec![ &ip("0.0.255.0")  ]).unwrap(), []);
    assert_eq!(decode_a(vec![ &ip("0.1.65.255") ]).unwrap(), fromto(65, 65));
    assert_eq!(decode_a(vec![ &ip("0.2.65.66")  ]).unwrap(), fromto(65, 66));

    // Note that we build these backwards
    assert_eq!(decode_a(vec![ &ip("1.67.255.255"), &ip("0.3.65.66") ]).unwrap(), fromto(65, 67));
    assert_eq!(decode_a(vec![ &ip("1.67.68.255"),  &ip("0.4.65.66") ]).unwrap(), fromto(65, 68));
    assert_eq!(decode_a(vec![ &ip("1.67.68.69"),   &ip("0.5.65.66") ]).unwrap(), fromto(65, 69));

    // And these ones, we build like sandwiches to be extra sure that it's order-agnostic
    assert_eq!(decode_a(vec![ &ip("1.67.68.69"), &ip("0.6.65.66"), &ip("2.70.255.255") ]).unwrap(), fromto(65, 70));
    assert_eq!(decode_a(vec![ &ip("1.67.68.69"), &ip("0.7.65.66"), &ip("2.70.71.255")  ]).unwrap(), fromto(65, 71));
    assert_eq!(decode_a(vec![ &ip("1.67.68.69"), &ip("0.8.65.66"), &ip("2.70.71.72")   ]).unwrap(), fromto(65, 72));
  }

  #[test]
  fn test_decode_a_with_extra() {
    // Most of these will be ignored
    assert_eq!(decode_a(vec![ &ip("1.1.1.1"), &ip("2.2.2.2"), &ip("3.3.3.3"), &ip("0.2.65.66"), &ip("4.4.4.4"), &ip("255.255.255.255") ]).unwrap(), fromto(65, 66));
  }

  #[test]
  fn test_decode_aaaa() {
    // Increasingly longer, but otherwise normal, addresses
    assert_eq!(decode_aaaa(vec![ &ip6("0000::")                                  ]).unwrap(), []);
    assert_eq!(decode_aaaa(vec![ &ip6("0001:41ff::")                             ]).unwrap(), fromto(65, 65));
    assert_eq!(decode_aaaa(vec![ &ip6("0002:4142::")                             ]).unwrap(), fromto(65, 66));
    assert_eq!(decode_aaaa(vec![ &ip6("0003:4142:43ff::")                        ]).unwrap(), fromto(65, 67));
    assert_eq!(decode_aaaa(vec![ &ip6("0004:4142:4344::")                        ]).unwrap(), fromto(65, 68));
    assert_eq!(decode_aaaa(vec![ &ip6("0005:4142:4344:45ff::")                   ]).unwrap(), fromto(65, 69));
    assert_eq!(decode_aaaa(vec![ &ip6("0006:4142:4344:4546::")                   ]).unwrap(), fromto(65, 70));
    assert_eq!(decode_aaaa(vec![ &ip6("0007:4142:4344:4546:47ff::")              ]).unwrap(), fromto(65, 71));
    assert_eq!(decode_aaaa(vec![ &ip6("0008:4142:4344:4546:4748::")              ]).unwrap(), fromto(65, 72));
    assert_eq!(decode_aaaa(vec![ &ip6("0009:4142:4344:4546:4748:49ff::")         ]).unwrap(), fromto(65, 73));
    assert_eq!(decode_aaaa(vec![ &ip6("000a:4142:4344:4546:4748:494a::")         ]).unwrap(), fromto(65, 74));
    assert_eq!(decode_aaaa(vec![ &ip6("000b:4142:4344:4546:4748:494a:4bff::")    ]).unwrap(), fromto(65, 75));
    assert_eq!(decode_aaaa(vec![ &ip6("000c:4142:4344:4546:4748:494a:4b4c::")    ]).unwrap(), fromto(65, 76));
    assert_eq!(decode_aaaa(vec![ &ip6("000d:4142:4344:4546:4748:494a:4b4c:4dff") ]).unwrap(), fromto(65, 77));
    assert_eq!(decode_aaaa(vec![ &ip6("000e:4142:4344:4546:4748:494a:4b4c:4d4e") ]).unwrap(), fromto(65, 78));

    assert_eq!(decode_aaaa(vec![
      &ip6("000f:4142:4344:4546:4748:494a:4b4c:4d4e"),
      &ip6("014f::"),
    ]).unwrap(), fromto(65, 79));

    assert_eq!(decode_aaaa(vec![
      &ip6("001d:4142:4344:4546:4748:494a:4b4c:4d4e"),
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"),
    ]).unwrap(), fromto(65, 93));

    assert_eq!(decode_aaaa(vec![
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"),
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"),
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"),
    ]).unwrap(), fromto(65, 108));
  }

  #[test]
  fn test_decode_aaaa_shuffled() {
    assert_eq!(decode_aaaa(vec![
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
    ]).unwrap(), fromto(65, 108));
    assert_eq!(decode_aaaa(vec![
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
    ]).unwrap(), fromto(65, 108));
    assert_eq!(decode_aaaa(vec![
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
    ]).unwrap(), fromto(65, 108));
    assert_eq!(decode_aaaa(vec![
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
    ]).unwrap(), fromto(65, 108));
    assert_eq!(decode_aaaa(vec![
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
    ]).unwrap(), fromto(65, 108));
    assert_eq!(decode_aaaa(vec![
      &ip6("025e:5f60:6162:6364:6566:6768:696a:6b6c"), // c
      &ip6("014f:5051:5253:5455:5657:5859:5a5b:5c5d"), // b
      &ip6("002c:4142:4344:4546:4748:494a:4b4c:4d4e"), // a
    ]).unwrap(), fromto(65, 108));
  }

  // Lazily get name
  fn n(name: &str) -> Name {
    Name::from_ascii(name).unwrap()
  }

  #[test]
  fn test_encode_name_basic() {
    // Basic functionality - making sure it encodes and splits
    let settings = Settings {
      name_identifier: NameIdentifier::Tag(n("a")),
      name_encoder: NameEncoder::Hex,
      segment_length: 8,
      record_type: RecordType::A,
    };
    assert_eq!(n("a"),                            encode_name("".as_bytes(),             &settings).unwrap());
    assert_eq!(n("a.41"),                         encode_name("A".as_bytes(),            &settings).unwrap());
    assert_eq!(n("a.4142"),                       encode_name("AB".as_bytes(),           &settings).unwrap());
    assert_eq!(n("a.414243"),                     encode_name("ABC".as_bytes(),          &settings).unwrap());
    assert_eq!(n("a.41424344"),                   encode_name("ABCD".as_bytes(),         &settings).unwrap());
    assert_eq!(n("a.41424344.45"),                encode_name("ABCDE".as_bytes(),        &settings).unwrap());
    assert_eq!(n("a.41424344.4546"),              encode_name("ABCDEF".as_bytes(),       &settings).unwrap());
    assert_eq!(n("a.41424344.454647"),            encode_name("ABCDEFG".as_bytes(),      &settings).unwrap());
    assert_eq!(n("a.41424344.45464748"),          encode_name("ABCDEFGH".as_bytes(),     &settings).unwrap());
    assert_eq!(n("a.41424344.45464748.49"),       encode_name("ABCDEFGHI".as_bytes(),    &settings).unwrap());
    assert_eq!(n("a.41424344.45464748.494a"),     encode_name("ABCDEFGHIJ".as_bytes(),   &settings).unwrap());
    assert_eq!(n("a.41424344.45464748.494a4b"),   encode_name("ABCDEFGHIJK".as_bytes(),  &settings).unwrap());
    assert_eq!(n("a.41424344.45464748.494a4b4c"), encode_name("ABCDEFGHIJKL".as_bytes(), &settings).unwrap());
  }

  #[test]
  fn test_encode_name_different_tag() {
    let settings = Settings {
      name_identifier: NameIdentifier::Tag(n("abcd")),
      name_encoder: NameEncoder::Hex,
      segment_length: 8,
      record_type: RecordType::A,
    };
    assert_eq!(n("abcd.41424344"), encode_name("ABCD".as_bytes(), &settings).unwrap());
  }

  #[test]
  fn test_encode_name_dotted_tag() {
    let settings = Settings {
      name_identifier: NameIdentifier::Tag(n("ab.cd")),
      name_encoder: NameEncoder::Hex,
      segment_length: 8,
      record_type: RecordType::A,
    };
    assert_eq!(n("ab.cd.41424344"), encode_name("ABCD".as_bytes(), &settings).unwrap());
  }


  #[test]
  fn test_encode_name_different_domain() {
    let settings = Settings {
      name_identifier: NameIdentifier::Domain(n("a")),
      name_encoder: NameEncoder::Hex,
      segment_length: 8,
      record_type: RecordType::A,
    };
    assert_eq!(n("a"),                   encode_name("".as_bytes(),         &settings).unwrap());
    assert_eq!(n("41414141.a"),          encode_name("AAAA".as_bytes(),     &settings).unwrap());
    assert_eq!(n("41414141.41414141.a"), encode_name("AAAAAAAA".as_bytes(), &settings).unwrap());
  }

  #[test]
  fn test_encode_name_base32() {
    let settings = Settings {
      name_identifier: NameIdentifier::Domain(n("a")),
      name_encoder: NameEncoder::Base32,
      segment_length: 8,
      record_type: RecordType::A,
    };
    assert_eq!(n("a"),                encode_name("".as_bytes(),         &settings).unwrap());
    assert_eq!(n("ifaucqi.a"),        encode_name("AAAA".as_bytes(),     &settings).unwrap());
    assert_eq!(n("ifaucqkb.ifauc.a"), encode_name("AAAAAAAA".as_bytes(), &settings).unwrap());

  }

  fn txt_record(s: &str) -> txt::TXT {
    txt::TXT::new(vec![String::from(s)])
  }

  #[test]
  fn test_decode_txt_hex() {
    let settings = Settings {
      name_identifier: NameIdentifier::Domain(Name::from_ascii("a.com").unwrap()),
      name_encoder: NameEncoder::Hex,
      segment_length: 8,
      record_type: RecordType::TXT,
    };

    assert_eq!(decode_txt(vec![&txt_record("")],         &settings).unwrap(), b"");
    assert_eq!(decode_txt(vec![&txt_record("41")],       &settings).unwrap(), b"A");
    assert_eq!(decode_txt(vec![&txt_record("4142")],     &settings).unwrap(), b"AB");
    assert_eq!(decode_txt(vec![&txt_record("414243")],   &settings).unwrap(), b"ABC");
    assert_eq!(decode_txt(vec![&txt_record("41424344")], &settings).unwrap(), b"ABCD");
  }

  #[test]
  fn test_decode_txt_base32() {
    let settings = Settings {
      name_identifier: NameIdentifier::Domain(Name::from_ascii("a.com").unwrap()),
      name_encoder: NameEncoder::Base32,
      segment_length: 8,
      record_type: RecordType::TXT,
    };

    assert_eq!(decode_txt(vec![&txt_record("")],        &settings).unwrap(), b"");
    assert_eq!(decode_txt(vec![&txt_record("ie")],      &settings).unwrap(), b"A");
    assert_eq!(decode_txt(vec![&txt_record("ifba")],    &settings).unwrap(), b"AB");
    assert_eq!(decode_txt(vec![&txt_record("ifbeg")],   &settings).unwrap(), b"ABC");
    assert_eq!(decode_txt(vec![&txt_record("ifbegra")], &settings).unwrap(), b"ABCD");

    // Make sure it's not case sensitive
    assert_eq!(decode_txt(vec![&txt_record("IFBEGRA")], &settings).unwrap(), b"ABCD");
  }

}
