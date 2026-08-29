# Modern Cryptography & Hashing Toolkit (TypeScript)

A misuse-resistant, high-level cryptography library with safe defaults, constant-time verification, and a clear API for hashing, password hashing, key derivation, symmetric encryption, HMAC, and digital signatures.

## Features

- **Safe hashing**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2 (MD5 and SHA-1 rejected)
- **HMAC**: Constant-time verification
- **Password hashing**: PBKDF2-SHA256 and scrypt with secure defaults
- **Key derivation**: PBKDF2 and scrypt
- **Symmetric encryption**: AES-256-GCM or ChaCha20-Poly1305 with automatic nonce management
- **Digital signatures**: Ed25519
- **Zero runtime dependencies** beyond Node.js `crypto`

## Installation

```bash
npm install crypto-toolkit-ts
```

## Quick Start

```typescript
import { hash, password, encrypt, sign } from 'crypto-toolkit-ts';

// Safe, deterministic hashing
const sha256 = hash.string('hello world', 'sha-256');
console.log(sha256);

const mac = hash.hmac('secret-key', 'message', 'sha-256');
console.log(hash.verifyHmac(mac, 'secret-key', 'message', 'sha-256'));

// Password hashing
const ph = password.hash('user-password');
console.log(password.verify('user-password', ph));

// Key derivation
const salt = Buffer.from('saltsaltsaltsalt', 'utf-8');
const key = password.derive('passphrase', salt, 32);

// Symmetric encryption
const ciphertext = encrypt.symmetric('sensitive data', key);
const plaintext = encrypt.decrypt(ciphertext, key);
console.log(plaintext);

// Digital signatures
const { privateKey, publicKey } = sign.generateKeypair();
const signature = sign.ed25519('message', privateKey);
console.log(sign.verify(signature, 'message', publicKey));
```

## Development

```bash
cd implementations/security/crypto-toolkit/typescript
npm install
npm run build
npm test
```

## License

MIT License
