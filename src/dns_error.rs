use std::error;
use std::fmt;
use hex;
use trust_dns::proto::error::ProtoError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum DnsErrorKind {
  ProtoErrorWrapper(ProtoError),
  StringError(String),
  ServerReturnedBadData(String),
  EncodingError(String),
}


#[derive(Debug, Clone)]
pub struct Error {
  pub kind: DnsErrorKind,
}

impl Error {
  pub fn new(kind: DnsErrorKind) -> Error {
    Error { kind }
  }

  pub fn bad_data(s: String) -> Error {
    Self::new(DnsErrorKind::ServerReturnedBadData(s))
  }

  pub fn encoding_error(s: String) -> Error {
    Self::new(DnsErrorKind::EncodingError(s))
  }
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "DnscatError: {:?}", self.kind)
  }
}

impl error::Error for Error {
  fn description(&self) -> &str {
    "A dnscat2 error"
  }

  fn cause(&self) -> Option<&error::Error> {
    None
  }
}

impl From<ProtoError> for Error {
  fn from(msg: ProtoError) -> Error {
    Error { kind: DnsErrorKind::ProtoErrorWrapper(msg) }
  }
}

impl From<hex::FromHexError> for Error {
  fn from(msg: hex::FromHexError) -> Error {
    Error::encoding_error(format!("Error decoding from hex: {:?}", msg))
  }
}

impl From<std::str::Utf8Error> for Error {
  fn from(msg: std::str::Utf8Error) -> Error {
    Error::encoding_error(format!("Error decoding from utf-8: {:?}", msg))
  }
}

impl From<String> for Error {
  fn from(msg: String) -> Error {
    Error { kind: DnsErrorKind::StringError(msg) }
  }
}
