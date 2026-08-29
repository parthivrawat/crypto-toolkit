use std::fmt;

/// Errors returned by the crypto toolkit.
#[derive(Debug)]
pub enum Error {
    /// An unsupported or insecure algorithm was requested.
    UnsupportedAlgorithm(String),
    /// A key has an incorrect length or is otherwise invalid.
    InvalidKey(String),
    /// Decryption or authentication failed.
    Decryption(String),
    /// Signature creation or verification failed.
    Signature(String),
    /// A password hash has an invalid format.
    InvalidHashFormat(String),
    /// Base64 decoding failed.
    Base64(String),
    /// Hex decoding failed.
    Hex(String),
    /// Failed to read random data.
    Random(String),
    /// A parameter was invalid.
    InvalidParameter(String),
    /// A wrapped underlying error.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedAlgorithm(msg) => write!(f, "unsupported or insecure algorithm: {msg}"),
            Error::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            Error::Decryption(msg) => write!(f, "decryption failed: {msg}"),
            Error::Signature(msg) => write!(f, "signature failed: {msg}"),
            Error::InvalidHashFormat(msg) => write!(f, "invalid hash format: {msg}"),
            Error::Base64(msg) => write!(f, "base64 error: {msg}"),
            Error::Hex(msg) => write!(f, "hex error: {msg}"),
            Error::Random(msg) => write!(f, "random error: {msg}"),
            Error::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
            Error::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for the crypto toolkit.
pub type Result<T> = std::result::Result<T, Error>;
