//! Digital signatures using Ed25519.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

/// Generate a new Ed25519 signing/verifying key pair.
pub fn generate_keypair() -> Result<(SigningKey, VerifyingKey)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Sign `message` using the provided Ed25519 `signing_key`.
pub fn ed25519(message: &str, signing_key: &SigningKey) -> Result<Vec<u8>> {
    Ok(signing_key.sign(message.as_bytes()).to_bytes().to_vec())
}

/// Verify an Ed25519 signature for `message` and `verifying_key`.
pub fn verify(signature: &[u8], message: &str, verifying_key: &VerifyingKey) -> Result<bool> {
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| Error::Signature(e.to_string()))?;
    Ok(verifying_key.verify(message.as_bytes(), &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (sk, pk) = generate_keypair().unwrap();
        let sig = ed25519("message", &sk).unwrap();
        assert!(verify(&sig, "message", &pk).unwrap());
        assert!(!verify(&sig, "other", &pk).unwrap());
    }
}
