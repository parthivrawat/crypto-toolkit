// Package sign provides digital signatures using Ed25519.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// GenerateKeypair returns a new Ed25519 private/public key pair.
func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

// Ed25519 signs message with the provided Ed25519 private key.
func Ed25519(message string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}
	return ed25519.Sign(privateKey, []byte(message)), nil
}

// Verify checks that signature is valid for message and publicKey.
func Verify(signature, message []byte, publicKey ed25519.PublicKey) bool {
	return ed25519.Verify(publicKey, message, signature)
}
