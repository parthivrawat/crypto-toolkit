//! Deterministic hashing and HMAC with safe, modern defaults.

use std::fs::File;
use std::io::Read;

use blake2::{Blake2b512, Blake2s256};
use digest::{Digest, DynDigest};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

macro_rules! hmac_with {
    ($key:expr, $data:expr, $alg:ty) => {{
        let mut mac = Hmac::<$alg>::new_from_slice($key)
            .map_err(|_| Error::InvalidKey("HMAC key length invalid".to_string()))?;
        mac.update($data);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }};
}

/// Supported digest algorithms. Parsing is centralized here so that
/// `string`, `file`, and `hmac` cannot drift apart.
#[derive(Clone, Copy, Debug)]
enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2b,
    Blake2s,
}

impl Algorithm {
    fn parse(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "sha-256" | "sha256" => Ok(Algorithm::Sha256),
            "sha-384" | "sha384" => Ok(Algorithm::Sha384),
            "sha-512" | "sha512" => Ok(Algorithm::Sha512),
            "sha3-256" | "sha3_256" => Ok(Algorithm::Sha3_256),
            "sha3-384" | "sha3_384" => Ok(Algorithm::Sha3_384),
            "sha3-512" | "sha3_512" => Ok(Algorithm::Sha3_512),
            "blake2b" => Ok(Algorithm::Blake2b),
            "blake2s" => Ok(Algorithm::Blake2s),
            _ => Err(Error::UnsupportedAlgorithm(name.to_string())),
        }
    }

    fn new_digest(&self) -> Box<dyn DynDigest> {
        match self {
            Algorithm::Sha256 => Box::new(Sha256::new()),
            Algorithm::Sha384 => Box::new(Sha384::new()),
            Algorithm::Sha512 => Box::new(Sha512::new()),
            Algorithm::Sha3_256 => Box::new(Sha3_256::new()),
            Algorithm::Sha3_384 => Box::new(Sha3_384::new()),
            Algorithm::Sha3_512 => Box::new(Sha3_512::new()),
            Algorithm::Blake2b => Box::new(Blake2b512::new()),
            Algorithm::Blake2s => Box::new(Blake2s256::new()),
        }
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Result<String> {
        match self {
            Algorithm::Sha256 => hmac_with!(key, data, Sha256),
            Algorithm::Sha384 => hmac_with!(key, data, Sha384),
            Algorithm::Sha512 => hmac_with!(key, data, Sha512),
            Algorithm::Sha3_256 => hmac_with!(key, data, Sha3_256),
            Algorithm::Sha3_384 => hmac_with!(key, data, Sha3_384),
            Algorithm::Sha3_512 => hmac_with!(key, data, Sha3_512),
            // BLAKE2 is already keyed-capable and is not exposed for HMAC.
            Algorithm::Blake2b | Algorithm::Blake2s => {
                Err(Error::UnsupportedAlgorithm("blake2 hmac".to_string()))
            }
        }
    }
}

/// Returns a safe, deterministic hex-encoded hash of `data`.
pub fn string(data: &str, algorithm: &str) -> Result<String> {
    let mut hasher = Algorithm::parse(algorithm)?.new_digest();
    hasher.update(data.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Returns the hex-encoded hash of a file.
pub fn file(path: &str, algorithm: &str) -> Result<String> {
    let mut hasher = Algorithm::parse(algorithm)?.new_digest();
    let mut file = File::open(path).map_err(|e| Error::Internal(e.to_string()))?;

    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| Error::Internal(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Returns a hex-encoded HMAC of `data` using `key` and `algorithm`.
///
/// `key` and `data` accept any `AsRef<[u8]>`, so both text (`&str`) and
/// binary inputs (`&[u8]`, `Vec<u8>`, byte arrays) are supported.
pub fn hmac(
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
    algorithm: &str,
) -> Result<String> {
    Algorithm::parse(algorithm)?.hmac(key.as_ref(), data.as_ref())
}

/// Verifies a hex-encoded HMAC in constant time.
pub fn verify_hmac(
    mac: &str,
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
    algorithm: &str,
) -> Result<bool> {
    let expected = hmac(key, data, algorithm)?;
    let a = hex::decode(mac).map_err(|e| Error::Hex(e.to_string()))?;
    let b = hex::decode(expected).map_err(|e| Error::Hex(e.to_string()))?;
    if a.len() != b.len() {
        return Ok(false);
    }
    Ok(a.as_slice().ct_eq(b.as_slice()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let got = string("hello world", "sha-256").unwrap();
        assert_eq!(got.len(), 64);
    }

    #[test]
    fn test_hmac() {
        let mac = hmac("key", "message", "sha-256").unwrap();
        assert!(verify_hmac(&mac, "key", "message", "sha-256").unwrap());
        assert!(!verify_hmac(&mac, "key", "tampered", "sha-256").unwrap());
    }

    #[test]
    fn test_hmac_binary_inputs() {
        let key = [0x00u8, 0xff, 0x10];
        let data = [0xdeu8, 0xad, 0xbe, 0xef];
        let mac = hmac(key, data, "sha-256").unwrap();
        assert!(verify_hmac(&mac, key, data, "sha-256").unwrap());
        assert!(!verify_hmac(&mac, key, b"other", "sha-256").unwrap());
    }

    #[test]
    fn test_rejects_weak() {
        assert!(string("test", "md5").is_err());
        assert!(string("test", "sha-1").is_err());
        assert!(string("test", "sha1").is_err());
        assert!(file("nonexistent", "md5").is_err());
        assert!(hmac("k", "d", "sha-1").is_err());
        assert!(hmac("k", "d", "blake2b").is_err());
    }
}
