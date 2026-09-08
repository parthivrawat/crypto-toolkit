# Changelog

## 1.1.0 - 2026-09-08

- **Breaking:** `encrypt.decrypt` now returns a `Buffer` and takes `aad` instead
  of its fourth `encoding` parameter
- **Breaking:** new tokens use ciphertext version 2 with an AAD-bound header and
  are incompatible with version-1-only readers
- Added public APIs `encrypt.encrypt`, `encrypt.encryptString`, and
  `encrypt.decryptString`
- `password.hash` defaults to Argon2id when `crypto.argon2Sync` is available (Node >= 23.6)
- `password.verify` rejects hashes with empty salt/digest fields
- `encrypt.decryptString` uses strict UTF-8 decoding (invalid bytes now throw)
- Added `sign.generateKeypairRaw` for a raw-bytes Ed25519 key API
- `npm run clean` is now cross-platform
- Upgraded `bcrypt` to ^6 and `vitest`/`@vitest/coverage-v8` to ^4 (fixes all `npm audit` findings)
- Added cross-language test vectors, token mutation/fuzz tests, and edge-case coverage

## 1.0.0 - 2026-08-29

- Initial TypeScript release
- Safe hashing (SHA-2, SHA-3, BLAKE2) with HMAC
- Password hashing and key derivation (PBKDF2, scrypt)
- AEAD symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Ed25519 digital signatures
