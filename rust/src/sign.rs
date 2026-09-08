//! Digital signatures using Ed25519.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

/// Generate a new Ed25519 32-byte seed / 32-byte public key pair.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key.to_bytes(), verifying_key.to_bytes()))
}

/// Sign `message` using the provided 32-byte Ed25519 private seed.
pub fn ed25519(message: &str, private_key: &[u8]) -> Result<Vec<u8>> {
    let seed: &[u8; 32] = private_key.try_into()
        .map_err(|_| Error::InvalidKey("Ed25519 private key must be 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(seed);
    Ok(signing_key.sign(message.as_bytes()).to_bytes().to_vec())
}

/// Alias for `ed25519`.
pub fn sign(message: &str, private_key: &[u8]) -> Result<Vec<u8>> {
    ed25519(message, private_key)
}

/// Verify an Ed25519 signature for `message` and a 32-byte `public_key`.
pub fn verify(signature: &[u8], message: &str, public_key: &[u8]) -> Result<bool> {
    let bytes: &[u8; 32] = public_key.try_into()
        .map_err(|_| Error::InvalidKey("Ed25519 public key must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(bytes)
        .map_err(|e| Error::Signature(e.to_string()))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| Error::Signature(e.to_string()))?;
    Ok(verifying_key.verify(message.as_bytes(), &sig).is_ok())
}

/// Serialize a 32-byte Ed25519 private seed to PKCS#8 PEM.
pub fn private_key_to_pem(private_key: &[u8]) -> Result<String> {
    let seed: &[u8; 32] = private_key.try_into()
        .map_err(|_| Error::InvalidKey("Ed25519 private key must be 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(seed);
    signing_key
        .to_pkcs8_pem(LineEnding::default())
        .map(|s| s.to_string())
        .map_err(|e| Error::Internal(e.to_string()))
}

/// Load an Ed25519 private key from PKCS#8 PEM and return the 32-byte seed.
pub fn private_key_from_pem(pem: &str) -> Result<[u8; 32]> {
    let signing_key = SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
    Ok(signing_key.to_bytes())
}

/// Serialize a 32-byte Ed25519 public key to SPKI PEM.
pub fn public_key_to_pem(public_key: &[u8]) -> Result<String> {
    let bytes: &[u8; 32] = public_key.try_into()
        .map_err(|_| Error::InvalidKey("Ed25519 public key must be 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(bytes)
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
    verifying_key
        .to_public_key_pem(LineEnding::default())
        .map_err(|e| Error::Internal(e.to_string()))
}

/// Load an Ed25519 public key from SPKI PEM and return the 32-byte raw key.
pub fn public_key_from_pem(pem: &str) -> Result<[u8; 32]> {
    let verifying_key = VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
    Ok(verifying_key.to_bytes())
}

/// Convenience alias: serialize raw private key bytes to PEM.
pub fn serialize_private_key(private_key: &[u8]) -> Result<String> {
    private_key_to_pem(private_key)
}

/// Convenience alias: serialize raw public key bytes to PEM.
pub fn serialize_public_key(public_key: &[u8]) -> Result<String> {
    public_key_to_pem(public_key)
}

/// Convenience alias: load a private key from PEM and return raw bytes.
pub fn load_private_key(pem: &str) -> Result<[u8; 32]> {
    private_key_from_pem(pem)
}

/// Convenience alias: load a public key from PEM and return raw bytes.
pub fn load_public_key(pem: &str) -> Result<[u8; 32]> {
    public_key_from_pem(pem)
}
