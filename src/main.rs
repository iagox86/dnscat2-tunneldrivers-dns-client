extern crate trust_dns_resolver;
extern crate hex;

use std::net;
use std::error;
use std::io;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

pub fn decode_a(addresses: Vec<&net::Ipv4Addr>) -> Result<Vec<u8>, Box<error::Error>> {
  // Handle no data
  // TODO: Better error handling
  if addresses.len() == 0 {
    return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "oops! No addresses!")));
  }

  // Convert all the addresses to u8[4]
  let mut addresses: Vec<[u8; 4]> = addresses
    .into_iter()
    .map(|a| a.octets())
    .collect();
    //.sort_by(|a, b| { a[0].cmp(b[0]) });

  // Sort them by the first field
  addresses.sort_by(|a, b| a[0].cmp(&b[0]));

  // Trim off the first value and merge them all together
  let mut result: Vec<u8> = Vec::new();

  for address in addresses {
    result.extend_from_slice(&address[1..4]);
  }

  let encoded_len: usize = result.remove(0) as usize;
  result.truncate(encoded_len);

  // TODO: Better error handling
  if result.len() < encoded_len {
    return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "oops! Result.len() is too short!")));
  }

  return Ok(result);
}

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

  // TODO: Use system resolver
  //let mut resolver = Resolver::from_system_conf().unwrap();

  loop {
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    let s = hex::encode(s);

    let mut request = String::new();
    request.push_str("a.");
    request.push_str(&s[..]);

  // Lookup the IP addresses associated with a name.
    //let response: Vec<net::Ipv4Addr> = resolver.ipv4_lookup("a.4142434445464748494a4b4c4d4e4f.5051525354555657.5.8595a5b5c").unwrap().iter().collect();
    let response = decode_a(resolver.ipv4_lookup(&request[..]).unwrap().iter().collect());

    let response = match response {
      Ok(s) => Some(String::from_utf8(s)),
      _ => None,
    };
    println!("{:?}", response);
  }

//  // There can be many addresses associated with the name,
//  //  this can return IPv4 and/or IPv6 addresses
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

  #[test]
  fn test_decode_a() {
    // Increasingly longer, but otherwise normal, addresses
    assert_eq!(decode_a(vec![ ip("0.0.255.0")  ]).unwrap(), vec![]);
    assert_eq!(decode_a(vec![ ip("0.1.65.255") ]).unwrap(), vec![65]);
    assert_eq!(decode_a(vec![ ip("0.2.65.66")  ]).unwrap(), vec![65, 66]);

    // Note that we build these backwards
    assert_eq!(decode_a(vec![ ip("1.67.255.255"), ip("0.3.65.66") ]).unwrap(), vec![65, 66, 67]);
    assert_eq!(decode_a(vec![ ip("1.67.68.255"),  ip("0.4.65.66") ]).unwrap(), vec![65, 66, 67, 68]);
    assert_eq!(decode_a(vec![ ip("1.67.68.69"),   ip("0.5.65.66") ]).unwrap(), vec![65, 66, 67, 68, 69]);

    // And these ones, we build like sandwiches to be extra sure that it's order-agnostic
    assert_eq!(decode_a(vec![ ip("1.67.68.69"), ip("0.6.65.66"), ip("2.70.255.255") ]).unwrap(), vec![65, 66, 67, 68, 69, 70]);
    assert_eq!(decode_a(vec![ ip("1.67.68.69"), ip("0.7.65.66"), ip("2.70.71.255")  ]).unwrap(), vec![65, 66, 67, 68, 69, 70, 71]);
    assert_eq!(decode_a(vec![ ip("1.67.68.69"), ip("0.8.65.66"), ip("2.70.71.72")   ]).unwrap(), vec![65, 66, 67, 68, 69, 70, 71, 72]);

    // Most of these will be ignored
    assert_eq!(decode_a(vec![ ip("1.1.1.1"),ip("2.2.2.2"),ip("3.3.3.3"), ip("0.2.65.65"), ip("4.4.4.4"),ip("255.255.255.255") ]).unwrap(), vec![65, 65]);
  }
}
