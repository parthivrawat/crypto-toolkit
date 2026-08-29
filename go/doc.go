// Package cryptotoolkit provides a misuse-resistant, high-level cryptography
// library with safe defaults for hashing, password hashing, key derivation,
// symmetric encryption, HMAC, and digital signatures.
//
// # Sub-packages
//
//   - hash: deterministic hashing and HMAC with safe algorithms
//   - password: password hashing, verification, and key derivation
//   - encrypt: AEAD symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
//   - sign: digital signatures (Ed25519)
//
// # Quick Start
//
//	import (
//	    "fmt"
//	    "log"
//
//	    "github.com/parthivrawat/crypto-toolkit/go/encrypt"
//	    "github.com/parthivrawat/crypto-toolkit/go/hash"
//	    "github.com/parthivrawat/crypto-toolkit/go/password"
//	    "github.com/parthivrawat/crypto-toolkit/go/sign"
//	)
//
//	func main() {
//	    h, err := hash.String("hello world", "sha-256")
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println(h)
//
//	    mac, _ := hash.HMAC("secret-key", "message", "sha-256")
//	    fmt.Println(hash.VerifyHMAC(mac, "secret-key", "message", "sha-256"))
//
//	    ph, _ := password.Hash("user-password")
//	    fmt.Println(password.Verify("user-password", ph))
//
//	    salt := []byte("saltsaltsaltsalt")
//	    key, _ := password.Derive("passphrase", salt, 32, "pbkdf2_sha256")
//
//	    ciphertext, _ := encrypt.SymmetricString("sensitive data", key)
//	    plaintext, _ := encrypt.DecryptString(ciphertext, key)
//	    fmt.Println(plaintext)
//
//	    priv, pub, _ := sign.GenerateKeypair()
//	    sig, _ := sign.Ed25519("message", priv)
//	    fmt.Println(sign.Verify(sig, []byte("message"), pub))
//	}
//
// # Documentation
//
// For complete documentation, visit:
// https://pkg.go.dev/github.com/parthivrawat/crypto-toolkit/go
//
// # Source Code
//
// https://github.com/parthivrawat/crypto-toolkit
package cryptotoolkit
