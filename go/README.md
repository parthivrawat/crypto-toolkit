# Modern Cryptography & Hashing Toolkit (Go)

A misuse-resistant, high-level cryptography library with safe defaults, constant-time verification, and clear APIs for hashing, password hashing, key derivation, symmetric encryption, HMAC, and digital signatures.

## Features

- **Safe hashing**: SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2 (MD5 and SHA-1 rejected)
- **HMAC**: Constant-time verification
- **Password hashing**: Argon2id, scrypt, bcrypt, PBKDF2-SHA256
- **Key derivation**: PBKDF2 and scrypt
- **Symmetric encryption**: AES-256-GCM and ChaCha20-Poly1305 with automatic nonce management
- **Digital signatures**: Ed25519

## Installation

```bash
go get github.com/parthivrawat/crypto-toolkit/go@latest
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/parthivrawat/crypto-toolkit/go/encrypt"
    "github.com/parthivrawat/crypto-toolkit/go/hash"
    "github.com/parthivrawat/crypto-toolkit/go/password"
    "github.com/parthivrawat/crypto-toolkit/go/sign"
)

func main() {
    h, err := hash.String("hello world", "sha-256")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(h)

    mac, _ := hash.HMAC("secret-key", "message", "sha-256")
    fmt.Println(hash.VerifyHMAC(mac, "secret-key", "message", "sha-256"))

    ph, _ := password.Hash("user-password")
    fmt.Println(password.Verify("user-password", ph))

    salt := []byte("saltsaltsaltsalt")
    key, _ := password.Derive("passphrase", salt, 32, "pbkdf2_sha256")

    ciphertext, _ := encrypt.SymmetricString("sensitive data", key)
    plaintext, _ := encrypt.DecryptString(ciphertext, key)
    fmt.Println(plaintext)

    priv, pub, _ := sign.GenerateKeypair()
    sig, _ := sign.Ed25519("message", priv)
    fmt.Println(sign.Verify(sig, []byte("message"), pub))
}
```

## Development

```bash
cd implementations/security/crypto-toolkit/go
go mod tidy
go test ./...
go build ./...
```

## License

MIT License
