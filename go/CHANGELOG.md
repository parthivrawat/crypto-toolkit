# Changelog

## 1.1.0 - 2026-09-08

- `password.Verify` accepts `$2y$` bcrypt hashes; rejects hashes with empty salt/digest fields
- `sign.GenerateKeypair` return order documented via named results `(seed, publicKey, err)`
- `hash`: single `newHashFunc` validation point shared by `String`, `File`, and `HMAC`
- Added cross-language test vectors, token mutation/fuzz tests, and edge-case coverage

## 1.0.0 - 2026-08-29

- Initial Go release
- Safe hashing (SHA-2, SHA-3, BLAKE2) with HMAC
- Password hashing and key derivation (Argon2id, scrypt, bcrypt, PBKDF2)
- AEAD symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Ed25519 digital signatures
