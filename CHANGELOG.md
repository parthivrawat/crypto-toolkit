# Changelog

Coordinated releases across all four language packages. Each language also keeps
its own changelog (`go/CHANGELOG.md`, `python/CHANGELOG.md`, `rust/CHANGELOG.md`,
`typescript/CHANGELOG.md`) with package-specific details.

## Versioning & Tagging

- All four packages are released together under the same semantic version.
- Repository tags use the form `vX.Y.Z` for coordinated releases (e.g. `v1.1.0`),
  applied after every package's version field and changelog have been updated.
- Language-specific patch releases may use `go/vX.Y.Z`, `python/vX.Y.Z`,
  `rust/vX.Y.Z`, or `typescript/vX.Y.Z` when only one package is affected.

## 1.1.0 - 2026-09-08

Security hardening and API-alignment release across all four implementations.

### Go (`go/`)

- `password.Verify` accepts `$2y$` bcrypt hashes
- `sign.GenerateKeypair` return order documented via named results `(seed, publicKey, err)`
- `hash` package: single `newHashFunc` validation point shared by `String`, `File`, and `HMAC`
- Added negative tests for weak/unsupported algorithms and malformed inputs

### Python (`python/`)

- `password.derive` raises `InvalidKeyError` (not `AlgorithmError`) for bad salt/length
- `password.verify` logs malformed hashes at DEBUG instead of failing silently
- Added typed `HashOptions` (`TypedDict`) accepted by `hash`, `hash_with`, and `derive`
- mypy `disallow_untyped_defs = true`; `python_version` target raised to 3.10
- scrypt/PBKDF2 serializations verified against the Go/Rust formats

### Rust (`rust/`)

- `hash::hmac`/`verify_hmac` accept `impl AsRef<[u8]>` (binary keys and messages)
- `hash`: single `Algorithm` dispatcher for `string`/`file`/`hmac`
- Custom `DynDigest` trait replaced by `digest::DynDigest`
- `password::derive` honors `HashOptions`; added `HashOptions::validate()`

### TypeScript (`typescript/`)

- `password.hash` defaults to Argon2id when `crypto.argon2Sync` is available (Node >= 23.6)
- `encrypt.decryptString` uses strict UTF-8 decoding (invalid bytes now throw)
- Added `sign.generateKeypairRaw` for a raw-bytes key API
- `npm run clean` is now cross-platform (no `rm -rf`)
- Added negative unit tests (invalid keys, tampered/malformed ciphertext, unsupported algorithms)

### Repository

- Added `SECURITY.md` with reporting and disclosure policy
- Added `.github/workflows/ci.yml`: per-language test matrix plus `govulncheck`,
  `pip-audit`, `cargo audit`, and `npm audit`
- README documents the threat model and usage boundaries

## 1.0.0 - 2026-08-29

- Initial coordinated release of the Go, Python, Rust, and TypeScript packages
- Safe hashing (SHA-2, SHA-3, BLAKE2) with HMAC
- Password hashing and key derivation (Argon2id, scrypt, bcrypt, PBKDF2)
- AEAD symmetric encryption (AES-256-GCM, ChaCha20-Poly1305) with versioned headers
- Ed25519 digital signatures
