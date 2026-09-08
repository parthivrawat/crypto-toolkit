//! Symmetric AEAD encryption with safe, modern defaults.

use aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;

use crate::error::{Error, Result};

const VERSION: u8 = 2;

#[derive(Clone, Copy)]
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

    fn tag_len(&self) -> usize {
        16
    }
}

fn parse_algorithm(name: &str) -> Result<Algorithm> {
    match name.to_lowercase().as_str() {
        "aes-256-gcm" | "aes_256_gcm" => Ok(Algorithm::Aes256Gcm),
        "chacha20-poly1305" | "chacha20_poly1305" => Ok(Algorithm::ChaCha20Poly1305),
        _ => Err(Error::UnsupportedAlgorithm(name.to_string())),
    }
}

fn build_aad(version: u8, algo_id: u8, aad: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + aad.len() + nonce.len());
    out.push(version);
    out.push(algo_id);
    out.extend_from_slice(&(aad.len() as u16).to_be_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(nonce);
    out
}

/// Encrypt plaintext using AES-256-GCM.
pub fn encrypt(plaintext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    encrypt_with(plaintext, key, aad, "aes-256-gcm")
}

/// Encrypt a UTF-8 string using AES-256-GCM.
pub fn encrypt_string(plaintext: &str, key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    encrypt_with(plaintext.as_bytes(), key, aad, "aes-256-gcm")
}

/// Encrypt plaintext with the chosen algorithm.
pub fn encrypt_with(
    plaintext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
    algorithm: &str,
) -> Result<Vec<u8>> {
    let algorithm = parse_algorithm(algorithm)?;
    if key.len() != algorithm.key_len() {
        return Err(Error::InvalidKey(format!(
            "{} requires a {}-byte key",
            algorithm.name(),
            algorithm.key_len()
        )));
    }

    let user_aad = aad.unwrap_or(&[]);
    if user_aad.len() > u16::MAX as usize {
        return Err(Error::InvalidParameter(format!(
            "additional authenticated data length {} exceeds maximum of {} bytes",
            user_aad.len(),
            u16::MAX
        )));
    }
    let (nonce, sealed) = match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let aad_for_cipher = build_aad(VERSION, algorithm as u8, user_aad, nonce.as_slice());
            let ct = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        aad: &aad_for_cipher,
                        msg: plaintext,
                    },
                )
                .map_err(|e| Error::Internal(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let aad_for_cipher = build_aad(VERSION, algorithm as u8, user_aad, nonce.as_slice());
            let ct = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        aad: &aad_for_cipher,
                        msg: plaintext,
                    },
                )
                .map_err(|e| Error::Internal(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
    };

    let mut token = Vec::with_capacity(4 + user_aad.len() + nonce.len() + sealed.len());
    token.push(VERSION);
    token.push(algorithm as u8);
    token.extend_from_slice(&(user_aad.len() as u16).to_be_bytes());
    token.extend_from_slice(user_aad);
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&sealed);
    Ok(token)
}

/// Decrypt and authenticate a token.
pub fn decrypt(ciphertext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if ciphertext.len() < 2 {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }
    match ciphertext[0] {
        VERSION => decrypt_v2(ciphertext, key, aad),
        1 => {
            if aad.is_some() && !aad.unwrap().is_empty() {
                return Err(Error::Decryption(
                    "v1 ciphertext does not support AAD".to_string(),
                ));
            }
            decrypt_v1(ciphertext, key)
        }
        v => Err(Error::Decryption(format!("unsupported version {}", v))),
    }
}

/// Decrypt and authenticate a token, returning a string.
pub fn decrypt_string(ciphertext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<String> {
    let plaintext = decrypt(ciphertext, key, aad)?;
    String::from_utf8(plaintext).map_err(|e| Error::Decryption(e.to_string()))
}

fn decrypt_v2(ciphertext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if ciphertext.len() < 4 {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }
    let algo_id = ciphertext[1];
    let aad_len = u16::from_be_bytes([ciphertext[2], ciphertext[3]]) as usize;
    let aad_start = 4usize;
    let aad_end = aad_start + aad_len;
    if ciphertext.len() < aad_end {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }
    let stored_aad = &ciphertext[aad_start..aad_end];
    let expected_aad = aad.unwrap_or(&[]);
    if stored_aad != expected_aad {
        return Err(Error::Decryption(
            "additional authenticated data does not match".to_string(),
        ));
    }

    let algorithm = Algorithm::from_id(algo_id)
        .ok_or_else(|| Error::Decryption(format!("unknown algorithm id {}", algo_id)))?;
    if key.len() != algorithm.key_len() {
        return Err(Error::InvalidKey(format!(
            "{} requires a {}-byte key",
            algorithm.name(),
            algorithm.key_len()
        )));
    }
    if ciphertext.len() < aad_end + algorithm.nonce_len() + algorithm.tag_len() {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }

    let nonce = &ciphertext[aad_end..aad_end + algorithm.nonce_len()];
    let sealed = &ciphertext[aad_end + algorithm.nonce_len()..];
    let aad_for_cipher = build_aad(VERSION, algo_id, stored_aad, nonce);

    let plaintext = match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        aad: &aad_for_cipher,
                        msg: sealed,
                    },
                )
                .map_err(|e| Error::Decryption(e.to_string()))?
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = chacha20poly1305::Nonce::from_slice(nonce);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        aad: &aad_for_cipher,
                        msg: sealed,
                    },
                )
                .map_err(|e| Error::Decryption(e.to_string()))?
        }
    };

    Ok(plaintext)
}

fn decrypt_v1(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let algorithm = Algorithm::from_id(ciphertext[1])
        .ok_or_else(|| Error::Decryption(format!("unknown algorithm id {}", ciphertext[1])))?;
    if key.len() != algorithm.key_len() {
        return Err(Error::InvalidKey(format!(
            "{} requires a {}-byte key",
            algorithm.name(),
            algorithm.key_len()
        )));
    }
    if ciphertext.len() < 2 + algorithm.nonce_len() + algorithm.tag_len() {
        return Err(Error::Decryption("ciphertext too short".to_string()));
    }

    let nonce = &ciphertext[2..2 + algorithm.nonce_len()];
    let sealed = &ciphertext[2 + algorithm.nonce_len()..];

    let plaintext = match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = aes_gcm::Nonce::from_slice(nonce);
            cipher
                .decrypt(nonce, sealed)
                .map_err(|e| Error::Decryption(e.to_string()))?
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let nonce = chacha20poly1305::Nonce::from_slice(nonce);
            cipher
                .decrypt(nonce, sealed)
                .map_err(|e| Error::Decryption(e.to_string()))?
        }
    };

    Ok(plaintext)
}

/// Deprecated alias for `encrypt`.
pub fn symmetric(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    encrypt_string(plaintext, key, None)
}
