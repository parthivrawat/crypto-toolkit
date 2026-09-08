// Package sign provides digital signatures using Ed25519.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrInvalidKey is returned when a key has an incorrect length or format.
var ErrInvalidKey = errors.New("invalid ed25519 key")

// GenerateKeypair returns a new Ed25519 key pair as (seed, publicKey).
//
// The first return value is the 32-byte private seed and the second is the
// 32-byte public key. Note this order is the reverse of the standard
// library's ed25519.GenerateKey, which returns (public, private); the seed
// is returned first here because it is the value that must be stored.
func GenerateKeypair() (seed []byte, publicKey []byte, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return private.Seed(), public, nil
}

// Ed25519 signs message with the provided Ed25519 32-byte private seed.
func Ed25519(message string, privateKey []byte) ([]byte, error) {
	if len(privateKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: private key must be %d bytes", ErrInvalidKey, ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(priv, []byte(message)), nil
}

// Sign is an alias for Ed25519.
func Sign(message string, privateKey []byte) ([]byte, error) {
	return Ed25519(message, privateKey)
}

// Verify checks that signature is valid for message and publicKey.
func Verify(signature, message []byte, publicKey []byte) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("%w: public key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
	}
	return ed25519.Verify(publicKey, message, signature), nil
}

// PrivateKeyToPEM wraps a 32-byte seed in a PKCS#8 PEM string.
func PrivateKeyToPEM(seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("%w: seed must be %d bytes", ErrInvalidKey, ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// PrivateKeyFromPEM loads a 32-byte seed from a PKCS#8 PEM string.
func PrivateKeyFromPEM(pemText string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: invalid PEM", ErrInvalidKey)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: PEM does not contain an Ed25519 private key", ErrInvalidKey)
	}
	return priv.Seed(), nil
}

// PublicKeyToPEM wraps a 32-byte public key in an SPKI PEM string.
func PublicKeyToPEM(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: public key must be %d bytes", ErrInvalidKey, ed25519.PublicKeySize)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(publicKey))
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// PublicKeyFromPEM loads a 32-byte public key from an SPKI PEM string.
func PublicKeyFromPEM(pemText string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: invalid PEM", ErrInvalidKey)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: PEM does not contain an Ed25519 public key", ErrInvalidKey)
	}
	return []byte(pub), nil
}
