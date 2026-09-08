# Modern Cryptography & Hashing Toolkit

A misuse-resistant, high-level cryptography library providing hashing, encryption, password derivation, and digital signatures across Python, TypeScript, Go, and Rust.

## Overview

This toolkit offers a consistent API for common cryptographic operations. Use it to hash data, encrypt with authenticated ciphers, derive passwords, and create or verify Ed25519 signatures.

## Languages

| Language | Package | README |
|---|---|---|
| **Go** | `go get github.com/parthivrawat/crypto-toolkit/go` | [Go README](go/README.md) |
| **Python** | `pip install crypto-toolkit-py` | [Python README](python/README.md) |
| **Rust** | `cargo add modern-crypto-toolkit` | [Rust README](rust/README.md) |
| **TypeScript** | `npm install crypto-toolkit-ts` | [TypeScript README](typescript/README.md) |

## Repository Layout

```
crypto-toolkit/
├── go/            # Go module
├── python/        # Python package
├── rust/          # Rust crate
├── typescript/    # TypeScript/npm package
└── README.md      # This file
```

## Security

### Threat Model & Usage Boundaries

This library provides high-level, misuse-resistant building blocks for common
cryptographic tasks. It is designed for **application-layer** security needs:
hashing data, verifying integrity with HMAC, storing passwords, encrypting
discrete messages/records at rest, and signing with Ed25519.

It is **not** intended for, and does not protect against:

- **Transport security** — it is not a TLS/SSH replacement and provides no
  protocol, key exchange, forward secrecy, or certificate handling.
- **Streaming or large-file encryption** — `encrypt` buffers the full plaintext
  in memory and emits a single AEAD token. For large data, use a streaming
  construction (e.g. STREAM) or a dedicated file-encryption tool.
- **Compromised endpoints** — keys and plaintext are protected only while the
  host process and OS are trustworthy. No defense is provided against memory
  disclosure, keyloggers, or a malicious runtime.
- **Advanced side channels** — verification uses constant-time comparisons where
  the platform exposes them, but microarchitectural/physical attacks (power,
  EM, cache timing beyond standard practice) are out of scope.
- **Interoperability with arbitrary formats** — password hash strings use a
  project-defined serialization; see `CROSS_LANGUAGE_VECTORS.md` for which
  formats verify across languages.

General guidance:

- Prefer the defaults (`argon2id` password hashing, `aes-256-gcm` encryption).
- Store and transport the full token/hash string; it carries the algorithm and
  parameters needed for verification.
- Keep dependencies updated; CI runs `govulncheck`, `pip-audit`,
  `cargo audit`, and `npm audit` on pushes to `main` and pull requests
  targeting `main`.

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities.

## License

MIT License. See the LICENSE file in each language directory for details.
