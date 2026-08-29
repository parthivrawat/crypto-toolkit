//! Symmetric AEAD encryption with safe, modern defaults.

use aead::{Aead, AeadCore, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;

use crate::error::{Error, Result};

const VERSION: u8 = 1;

enum Algorithm {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

impl Algorithm {
    fn from_id(id: u8) -> Option<Algorithm> {
        match id {
            1 => Some(Algorithm::Aes256Gcm),
            2 => Some(Algorithm::ChaCha20Poly1305),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Algorithm::Aes256Gcm => "aes-256-gcm",
            Algorithm::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }
}

/// Encrypt a plaintext string using AES-256-GCM.
pub fn symmetric(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    symmetric_with(plaintext, key, "aes-256-gcm")
}

/// Encrypt a plaintext string with the chosen algorithm.
pub fn symmetric_with(plaintext: &str, key: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let algorithm = parse_algorithm(algorithm)?;
    if key.len() != algorithm.key_len() {
        return Err(Error::InvalidKey(format!(
            "{} requires a {}-byte key",
            algorithm.name(),
            algorithm.key_len()
        )));
    }

    let (nonce, ciphertext) = match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ct = cipher
                .encrypt(&nonce, plaintext.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ct = cipher
                .encrypt(&nonce, plaintext.as_bytes())
                .map_err(|e| Error::Internal(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
    };

    let mut token = Vec::with_capacity(2 + algorithm.nonce_len() + ciphertext.len());
    token.push(VERSION);
    token.push(algorithm as u8);
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&ciphertext);
    Ok(token)
}

fn parse_algorithm(name: &str) -> Result<Algorithm> {
    match name.to_lowercase().as_str() {
        "aes-256-gcm" | "aes_256_gcm" => Ok(Algorithm::Aes256Gcm),
        "chacha20-poly1305" | "chacha20_poly1305" => Ok(Algorithm::ChaCha20Poly1305),
        _ => Err(Error::UnsupportedAlgorithm(name.to_string())),
    }
}

/// Decrypt and authenticate a token, returning a string.
pub fn decrypt_string(ciphertext: &[u8], key: &[u8]) -> Result<String> {
    let plaintext = decrypt(ciphertext, key)?;
    String::from_utf8(plaintext).map_err(|e| Error::Decryption(e.to_string()))
}

/// Decrypt and authenticate a token.
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 2 {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }
    if ciphertext[0] != VERSION {
        return Err(Error::Decryption(format!("unsupported version {}", ciphertext[0])));
    }
    let algorithm = Algorithm::from_id(ciphertext[1])
        .ok_or_else(|| Error::Decryption(format!("unknown algorithm id {}", ciphertext[1])))?;
    if key.len() != algorithm.key_len() {
        return Err(Error::InvalidKey(format!(
            "{} requires a {}-byte key",
            algorithm.name(),
            algorithm.key_len()
        )));
    }
    if ciphertext.len() < 2 + algorithm.nonce_len() + 16 {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }

    let nonce_start = 2;
    let nonce_end = nonce_start + algorithm.nonce_len();
    let nonce = &ciphertext[nonce_start..nonce_end];
    let sealed = &ciphertext[nonce_end..];

    let plaintext = match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = aes_gcm::Nonce::from_slice(nonce);
            cipher.decrypt(nonce, sealed).map_err(|e| Error::Decryption(e.to_string()))?
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = chacha20poly1305::Nonce::from_slice(nonce);
            cipher.decrypt(nonce, sealed).map_err(|e| Error::Decryption(e.to_string()))?
        }
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = vec![0x78u8; 32];
        let ct = symmetric("sensitive data", &key).unwrap();
        let pt = decrypt_string(&ct, &key).unwrap();
        assert_eq!(pt, "sensitive data");
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = vec![0x12u8; 32];
        let ct = symmetric_with("sensitive data", &key, "chacha20-poly1305").unwrap();
        let pt = decrypt_string(&ct, &key).unwrap();
        assert_eq!(pt, "sensitive data");
    }

    #[test]
    fn test_tampering_rejected() {
        let key = vec![0xabu8; 32];
        let mut ct = symmetric("data", &key).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(decrypt(&ct, &key).is_err());
    }
}
