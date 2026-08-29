//! Deterministic hashing and HMAC with safe, modern defaults.

use std::fs::File;
use std::io::Read;

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use blake2::{Blake2b512, Blake2s256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

macro_rules! hmac_with {
    ($key:expr, $data:expr, $alg:ty) => {{
        let mut mac = Hmac::<$alg>::new_from_slice($key.as_bytes())
            .map_err(|_| Error::InvalidKey("HMAC key length invalid".to_string()))?;
        mac.update($data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }};
}

/// Returns a safe, deterministic hex-encoded hash of `data`.
pub fn string(data: &str, algorithm: &str) -> Result<String> {
    match algorithm.to_lowercase().as_str() {
        "sha-256" | "sha256" => Ok(hex::encode(Sha256::new().chain_update(data).finalize())),
        "sha-384" | "sha384" => Ok(hex::encode(Sha384::new().chain_update(data).finalize())),
        "sha-512" | "sha512" => Ok(hex::encode(Sha512::new().chain_update(data).finalize())),
        "sha3-256" | "sha3_256" => Ok(hex::encode(Sha3_256::new().chain_update(data).finalize())),
        "sha3-384" | "sha3_384" => Ok(hex::encode(Sha3_384::new().chain_update(data).finalize())),
        "sha3-512" | "sha3_512" => Ok(hex::encode(Sha3_512::new().chain_update(data).finalize())),
        "blake2b" => Ok(hex::encode(Blake2b512::new().chain_update(data).finalize())),
        "blake2s" => Ok(hex::encode(Blake2s256::new().chain_update(data).finalize())),
        "md5" | "sha-1" | "sha1" => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
        _ => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

/// Returns the hex-encoded hash of a file.
pub fn file(path: &str, algorithm: &str) -> Result<String> {
    let mut file = File::open(path).map_err(|e| Error::Internal(e.to_string()))?;
    let mut hasher = match algorithm.to_lowercase().as_str() {
        "sha-256" | "sha256" => Box::new(Sha256::new()) as Box<dyn DynDigest>,
        "sha-384" | "sha384" => Box::new(Sha384::new()) as Box<dyn DynDigest>,
        "sha-512" | "sha512" => Box::new(Sha512::new()) as Box<dyn DynDigest>,
        "sha3-256" | "sha3_256" => Box::new(Sha3_256::new()) as Box<dyn DynDigest>,
        "sha3-384" | "sha3_384" => Box::new(Sha3_384::new()) as Box<dyn DynDigest>,
        "sha3-512" | "sha3_512" => Box::new(Sha3_512::new()) as Box<dyn DynDigest>,
        "blake2b" => Box::new(Blake2b512::new()) as Box<dyn DynDigest>,
        "blake2s" => Box::new(Blake2s256::new()) as Box<dyn DynDigest>,
        "md5" | "sha-1" | "sha1" => return Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
        _ => return Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    };

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
pub fn hmac(key: &str, data: &str, algorithm: &str) -> Result<String> {
    match algorithm.to_lowercase().as_str() {
        "sha-256" | "sha256" => Ok(hmac_with!(key, data, Sha256)),
        "sha-384" | "sha384" => Ok(hmac_with!(key, data, Sha384)),
        "sha-512" | "sha512" => Ok(hmac_with!(key, data, Sha512)),
        "sha3-256" | "sha3_256" => Ok(hmac_with!(key, data, Sha3_256)),
        "sha3-384" | "sha3_384" => Ok(hmac_with!(key, data, Sha3_384)),
        "sha3-512" | "sha3_512" => Ok(hmac_with!(key, data, Sha3_512)),
        "md5" | "sha-1" | "sha1" | "blake2b" | "blake2s" => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
        _ => Err(Error::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

/// Verifies a hex-encoded HMAC in constant time.
pub fn verify_hmac(mac: &str, key: &str, data: &str, algorithm: &str) -> Result<bool> {
    let expected = hmac(key, data, algorithm)?;
    let a = hex::decode(mac).map_err(|e| Error::Hex(e.to_string()))?;
    let b = hex::decode(expected).map_err(|e| Error::Hex(e.to_string()))?;
    if a.len() != b.len() {
        return Ok(false);
    }
    Ok(a.as_slice().ct_eq(b.as_slice()).into())
}

// Trait object helper for streaming file hashing.
trait DynDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

impl<D: Digest> DynDigest for D {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }
    fn finalize(self: Box<Self>) -> Vec<u8> {
        Digest::finalize(*self).to_vec()
    }
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
    fn test_rejects_weak() {
        assert!(string("test", "md5").is_err());
        assert!(string("test", "sha-1").is_err());
    }
}
