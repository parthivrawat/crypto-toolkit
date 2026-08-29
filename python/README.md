# Modern Cryptography & Hashing Toolkit (Python)

A misuse-resistant, high-level cryptography library with safe defaults, constant-time verification, and a clear API for hashing, password hashing, key derivation, symmetric encryption, HMAC, and digital signatures.

## Features

- **Safe hashing**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2 (MD5 and SHA-1 rejected)
- **HMAC**: Constant-time verification
- **Password hashing**: PBKDF2-SHA256, scrypt, Argon2id, bcrypt with adaptive costs
- **Key derivation**: PBKDF2 and scrypt
- **Symmetric encryption**: AES-256-GCM or ChaCha20-Poly1305 with automatic nonce management
- **Digital signatures**: Ed25519
- **Zero runtime dependencies** for core hashing, HMAC, and key derivation
- **Optional extras** for AEAD encryption and signatures (`[crypto]`), Argon2id (`[argon2]`), and bcrypt (`[bcrypt]`)

## Installation

```bash
pip install crypto-toolkit-py
```

With all optional dependencies:

```bash
pip install "crypto-toolkit-py[full]"
```

## Quick Start

```python
from crypto_toolkit import hash, password, encrypt, sign

# Safe, deterministic hashing
sha256 = hash.string('hello world', algorithm='sha-256')
print(sha256)

mac = hash.hmac('secret-key', 'message', algorithm='sha-256')
assert hash.verify_hmac(mac, 'secret-key', 'message', algorithm='sha-256')

# Password hashing
ph = password.hash('user-password')
assert password.verify('user-password', ph)

# Key derivation
salt = b'16-or-more-random-bytes'
key = password.derive('passphrase', salt=salt, length=32)

# Symmetric encryption (requires cryptography)
ciphertext = encrypt.symmetric('sensitive data', key=key)
plaintext = encrypt.decrypt(ciphertext, key=key)
assert plaintext == 'sensitive data'

# Digital signatures (requires cryptography)
private_key, public_key = sign.generate_keypair()
signature = sign.ed25519('message', private_key=private_key)
assert sign.verify(signature, 'message', public_key=public_key)
```

## Development

```bash
cd implementations/security/crypto-toolkit/python
pip install -e ".[dev,full]"
pytest test_crypto_toolkit.py -v
```

## License

MIT License
