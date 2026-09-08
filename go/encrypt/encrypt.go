// Package encrypt provides misuse-resistant AEAD symmetric encryption using
// AES-256-GCM and ChaCha20-Poly1305. Nonces are generated automatically and
// never reused.
package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const version byte = 2

type algorithmSpec struct {
	id       byte
	keyLen   int
	nonceLen int
	tagLen   int
	newAEAD  func(key []byte) (cipher.AEAD, error)
}

var algorithms = map[string]algorithmSpec{
	"aes-256-gcm": {
		id:       1,
		keyLen:   32,
		nonceLen: 12,
		tagLen:   16,
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
		tagLen:   16,
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

// ErrUnsupportedAlgorithm is returned when an unknown algorithm is requested.
var ErrUnsupportedAlgorithm = errors.New("unsupported or insecure algorithm")

func getSpec(name string) (algorithmSpec, error) {
	name = normalizeAlgorithm(name)
	spec, ok := algorithms[name]
	if !ok {
		return algorithmSpec{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, name)
	}
	return spec, nil
}

func normalizeAlgorithm(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func buildAAD(version, algoID byte, aad, nonce []byte) []byte {
	if aad == nil {
		aad = []byte{}
	}
	aadLen := make([]byte, 2)
	binary.BigEndian.PutUint16(aadLen, uint16(len(aad)))
	return append([]byte{version, algoID}, append(aadLen, append(aad, nonce...)...)...)
}

// Encrypt encrypts plaintext using AES-256-GCM by default.
func Encrypt(plaintext, key, aad []byte) ([]byte, error) {
	return EncryptWith(plaintext, key, aad, "")
}

// EncryptString encrypts a string using AES-256-GCM by default.
func EncryptString(plaintext string, key, aad []byte) ([]byte, error) {
	return EncryptWith([]byte(plaintext), key, aad, "")
}

// EncryptStringWith encrypts a string with the chosen algorithm.
func EncryptStringWith(plaintext string, key, aad []byte, algorithm string) ([]byte, error) {
	return EncryptWith([]byte(plaintext), key, aad, algorithm)
}

// EncryptWith encrypts plaintext with the chosen algorithm and optional AAD.
func EncryptWith(plaintext, key, aad []byte, algorithm string) ([]byte, error) {
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}
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

	aadForCipher := buildAAD(version, spec.id, aad, nonce)
	sealed := aead.Seal(nil, nonce, plaintext, aadForCipher)

	if aad == nil {
		aad = []byte{}
	}
	aadLen := make([]byte, 2)
	binary.BigEndian.PutUint16(aadLen, uint16(len(aad)))

	token := make([]byte, 0, 2+2+len(aad)+len(nonce)+len(sealed))
	token = append(token, version, spec.id)
	token = append(token, aadLen...)
	token = append(token, aad...)
	token = append(token, nonce...)
	token = append(token, sealed...)
	return token, nil
}

// DecryptString decrypts and authenticates a token, returning a string.
func DecryptString(token, key, aad []byte) (string, error) {
	pt, err := Decrypt(token, key, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Decrypt decrypts and authenticates a token.
func Decrypt(token, key, aad []byte) ([]byte, error) {
	if len(token) < 2 {
		return nil, ErrDecryption
	}

	switch token[0] {
	case version:
		return decryptV2(token, key, aad)
	case 1:
		if aad != nil && len(aad) > 0 {
			return nil, fmt.Errorf("%w: v1 ciphertext does not support AAD", ErrDecryption)
		}
		return decryptV1(token, key)
	default:
		return nil, fmt.Errorf("unsupported ciphertext version: %d", token[0])
	}
}

func decryptV2(token, key, aad []byte) ([]byte, error) {
	if len(token) < 4 {
		return nil, ErrDecryption
	}

	algoID := token[1]
	aadLen := binary.BigEndian.Uint16(token[2:4])

	if len(token) < int(4+aadLen) {
		return nil, ErrDecryption
	}
	storedAAD := token[4 : 4+aadLen]

	if !bytes.Equal(aad, storedAAD) {
		if aad == nil && aadLen == 0 {
			// ok
		} else {
			return nil, fmt.Errorf("%w: additional authenticated data does not match", ErrDecryption)
		}
	}

	name, ok := idToName[algoID]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm id: %d", algoID)
	}
	spec, err := getSpec(name)
	if err != nil {
		return nil, err
	}
	if len(key) != spec.keyLen {
		return nil, fmt.Errorf("%w: %s requires a %d-byte key", ErrInvalidKey, name, spec.keyLen)
	}

	nonceStart := 4 + int(aadLen)
	nonceEnd := nonceStart + spec.nonceLen
	if len(token) < nonceEnd+spec.tagLen {
		return nil, ErrDecryption
	}
	nonce := token[nonceStart:nonceEnd]
	sealed := token[nonceEnd:]

	aadForCipher := buildAAD(version, algoID, storedAAD, nonce)
	aead, err := spec.newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, sealed, aadForCipher)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	return plaintext, nil
}

func decryptV1(token, key []byte) ([]byte, error) {
	name, ok := idToName[token[1]]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm id: %d", token[1])
	}
	spec, err := getSpec(name)
	if err != nil {
		return nil, err
	}
	if len(key) != spec.keyLen {
		return nil, fmt.Errorf("%w: %s requires a %d-byte key", ErrInvalidKey, name, spec.keyLen)
	}
	if len(token) < 2+spec.nonceLen+spec.tagLen {
		return nil, ErrDecryption
	}
	nonce := token[2 : 2+spec.nonceLen]
	sealed := token[2+spec.nonceLen:]

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

// Symmetric encrypts plaintext using AES-256-GCM (deprecated, use Encrypt).
func Symmetric(plaintext, key []byte) ([]byte, error) {
	return Encrypt(plaintext, key, nil)
}

// SymmetricString encrypts a string using AES-256-GCM (deprecated, use EncryptString).
func SymmetricString(plaintext string, key []byte) ([]byte, error) {
	return EncryptString(plaintext, key, nil)
}

// SymmetricWith encrypts plaintext with the chosen algorithm (deprecated, use Encrypt).
func SymmetricWith(plaintext, key []byte, algorithm string) ([]byte, error) {
	return EncryptWith(plaintext, key, nil, algorithm)
}

// SymmetricStringWith encrypts a string with the chosen algorithm (deprecated, use EncryptString).
func SymmetricStringWith(plaintext string, key []byte, algorithm string) ([]byte, error) {
	return EncryptStringWith(plaintext, key, nil, algorithm)
}
