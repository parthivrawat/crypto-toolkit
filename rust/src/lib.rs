//! Modern Cryptography & Hashing Toolkit (Rust)
//!
//! A misuse-resistant, high-level cryptography library with safe defaults,
//! constant-time verification, and clear APIs for hashing, password hashing,
//! key derivation, symmetric encryption, HMAC, and digital signatures.
//!
//! # Sub-modules
//!
//! - [`hash`]: deterministic hashing and HMAC
//! - [`password`]: password hashing, verification, and key derivation
//! - [`encrypt`]: AEAD symmetric encryption
//! - [`sign`]: Ed25519 digital signatures
//!
//! # Examples
//!
//! ```
//! use modern_crypto_toolkit::{hash, password, encrypt, sign};
//!
//! let sha256 = hash::string("hello world", "sha-256").unwrap();
//! let mac = hash::hmac("secret-key", "message", "sha-256").unwrap();
//! assert!(hash::verify_hmac(&mac, "secret-key", "message", "sha-256").unwrap());
//!
//! let ph = password::hash("user-password").unwrap();
//! assert!(password::verify("user-password", &ph).unwrap());
//!
//! let salt = b"saltsaltsaltsalt";
//! let key = password::derive("passphrase", salt, 32, Some("pbkdf2_sha256")).unwrap();
//!
//! let ciphertext = encrypt::symmetric("sensitive data", &key).unwrap();
//! let plaintext = encrypt::decrypt_string(&ciphertext, &key).unwrap();
//! assert_eq!(plaintext, "sensitive data");
//!
//! let (sk, pk) = sign::generate_keypair().unwrap();
//! let signature = sign::ed25519("message", &sk).unwrap();
//! assert!(sign::verify(&signature, "message", &pk).unwrap());
//! ```

pub mod encrypt;
pub mod error;
pub mod hash;
pub mod password;
pub mod sign;

pub use error::{Error, Result};
