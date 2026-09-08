# Changelog

## 1.1.0 - 2026-09-08

- `password.verify` rejects hashes with empty salt/digest fields and logs malformed hashes at DEBUG
- Added typed `HashOptions` (`TypedDict`) accepted by `hash`, `hash_with`, and `derive`
- mypy `disallow_untyped_defs = true`; mypy target raised to Python 3.10
- Added cross-language test vectors, token mutation/fuzz tests, and edge-case coverage

## 1.0.0 - 2026-08-29

- Initial Python release
- Safe hashing (SHA-2, SHA-3, BLAKE2) with HMAC
- Password hashing and key derivation (PBKDF2, scrypt, Argon2id, bcrypt)
- AEAD symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Ed25519 digital signatures
