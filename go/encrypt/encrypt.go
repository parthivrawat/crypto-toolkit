// Package encrypt provides misuse-resistant AEAD symmetric encryption using
// AES-256-GCM and ChaCha20-Poly1305. Nonces are generated automatically and
// never reused.
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const version byte = 1

type algorithmSpec struct {
	id       byte
	keyLen   int
	nonceLen int
	newAEAD  func(key []byte) (cipher.AEAD, error)
}

var algorithms = map[string]algorithmSpec{
	"aes-256-gcm": {
		id:       1,
		keyLen:   32,
		nonceLen: 12,
		newAEAD: func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		},
	},
	"chacha20-poly1305": {
		id:       2,
		keyLen:   32,
		nonceLen: 12,
		newAEAD:  chacha20poly1305.New,
	},
}

var idToName = map[byte]string{}

func init() {
	for name, spec := range algorithms {
		idToName[spec.id] = name
	}
}

// ErrDecryption is returned when decryption or authentication fails.
var ErrDecryption = errors.New("decryption or authentication failed")

// ErrInvalidKey is returned when a key has an incorrect length.
var ErrInvalidKey = errors.New("invalid key length")

func getSpec(name string) (algorithmSpec, error) {
	spec, ok := algorithms[name]
	if !ok {
		return algorithmSpec{}, fmt.Errorf("unsupported cipher: %s", name)
	}
	return spec, nil
}

// SymmetricString encrypts a string using AES-256-GCM.
func SymmetricString(plaintext string, key []byte) ([]byte, error) {
	return Symmetric([]byte(plaintext), key)
}

// SymmetricStringWith encrypts a string with the chosen algorithm.
func SymmetricStringWith(plaintext string, key []byte, algorithm string) ([]byte, error) {
	return SymmetricWith([]byte(plaintext), key, algorithm)
}

// Symmetric encrypts plaintext using AES-256-GCM.
func Symmetric(plaintext, key []byte) ([]byte, error) {
	return SymmetricWith(plaintext, key, "aes-256-gcm")
}

// SymmetricWith encrypts plaintext with the chosen algorithm.
func SymmetricWith(plaintext, key []byte, algorithm string) ([]byte, error) {
	spec, err := getSpec(algorithm)
	if err != nil {
		return nil, err
	}
	if len(key) != spec.keyLen {
		return nil, fmt.Errorf("%w: %s requires a %d-byte key", ErrInvalidKey, algorithm, spec.keyLen)
	}

	nonce := make([]byte, spec.nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aead, err := spec.newAEAD(key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	token := make([]byte, 2+len(nonce)+len(ciphertext))
	token[0] = version
	token[1] = spec.id
	copy(token[2:], nonce)
	copy(token[2+len(nonce):], ciphertext)
	return token, nil
}

// DecryptString decrypts and authenticates a token, returning a string.
func DecryptString(ciphertext, key []byte) (string, error) {
	pt, err := Decrypt(ciphertext, key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Decrypt decrypts and authenticates a token.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, ErrDecryption
	}
	if ciphertext[0] != version {
		return nil, fmt.Errorf("unsupported ciphertext version: %d", ciphertext[0])
	}
	name, ok := idToName[ciphertext[1]]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm id: %d", ciphertext[1])
	}
	spec, err := getSpec(name)
	if err != nil {
		return nil, err
	}
	if len(key) != spec.keyLen {
		return nil, fmt.Errorf("%w: %s requires a %d-byte key", ErrInvalidKey, name, spec.keyLen)
	}
	if len(ciphertext) < 2+spec.nonceLen+16 {
		return nil, ErrDecryption
	}
	nonce := ciphertext[2 : 2+spec.nonceLen]
	sealed := ciphertext[2+spec.nonceLen:]

	aead, err := spec.newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	return plaintext, nil
}
