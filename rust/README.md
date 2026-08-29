# Modern Cryptography & Hashing Toolkit (Rust)

A misuse-resistant, high-level cryptography library with safe defaults, constant-time verification, and clear APIs for hashing, password hashing, key derivation, symmetric encryption, HMAC, and digital signatures.

## Features

- **Safe hashing**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2
- **HMAC**: Constant-time verification
- **Password hashing**: Argon2id, scrypt, bcrypt, PBKDF2-SHA256
- **Key derivation**: PBKDF2 and scrypt
- **Symmetric encryption**: AES-256-GCM and ChaCha20-Poly1305
- **Digital signatures**: Ed25519

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
modern-crypto-toolkit = "1.0.0"
```

Or use cargo add:

```bash
cargo add modern-crypto-toolkit
```

## Quick Start

```rust
use modern_crypto_toolkit::{hash, password, encrypt, sign};

let sha256 = hash::string("hello world", "sha-256").unwrap();
let mac = hash::hmac("secret-key", "message", "sha-256").unwrap();
assert!(hash::verify_hmac(&mac, "secret-key", "message", "sha-256").unwrap());

let ph = password::hash("user-password").unwrap();
assert!(password::verify("user-password", &ph).unwrap());

let salt = b"saltsaltsaltsalt";
let key = password::derive("passphrase", salt, 32, Some("pbkdf2_sha256")).unwrap();

let ciphertext = encrypt::symmetric("sensitive data", &key).unwrap();
let plaintext = encrypt::decrypt_string(&ciphertext, &key).unwrap();
assert_eq!(plaintext, "sensitive data");

let (sk, pk) = sign::generate_keypair().unwrap();
let signature = sign::ed25519("message", &sk).unwrap();
assert!(sign::verify(&signature, "message", &pk).unwrap());
```

## Development

```bash
cd implementations/security/crypto-toolkit/rust
cargo build
cargo test
cargo doc --no-deps
```

## License

MIT License
