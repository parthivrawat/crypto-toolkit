// Package hash provides deterministic hashing and HMAC with safe, modern
// defaults. Insecure algorithms such as MD5 and SHA-1 are rejected.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	stdhash "hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

// ErrUnsupportedAlgorithm is returned when an unsafe or unknown algorithm is requested.
var ErrUnsupportedAlgorithm = errors.New("unsupported or insecure hashing algorithm")

var allowed = map[string]func() stdhash.Hash{
	"sha-256":  sha256.New,
	"sha-384":  sha512.New384,
	"sha-512":  sha512.New,
	"sha3-256": sha3.New256,
	"sha3-384": sha3.New384,
	"sha3-512": sha3.New512,
	"blake2b": func() stdhash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	},
	"blake2s": func() stdhash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	},
}

func normalize(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func newHash(name string) (stdhash.Hash, error) {
	name = normalize(name)
	if name == "md5" || name == "sha-1" || name == "sha1" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, name)
	}
	f, ok := allowed[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, name)
	}
	return f(), nil
}

// String returns a safe, deterministic hex-encoded hash of data.
func String(data string, algorithm string) (string, error) {
	h, err := newHash(algorithm)
	if err != nil {
		return "", err
	}
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File returns the hex-encoded hash of a file.
func File(path string, algorithm string) (string, error) {
	h, err := newHash(algorithm)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.CopyBuffer(h, f, make([]byte, 8192)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HMAC returns a hex-encoded HMAC of data using key and algorithm.
func HMAC(key, data, algorithm string) (string, error) {
	name := normalize(algorithm)
	f, ok := allowed[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
	mac := hmac.New(f, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC verifies a hex-encoded HMAC in constant time.
func VerifyHMAC(mac, key, data, algorithm string) (bool, error) {
	expected, err := HMAC(key, data, algorithm)
	if err != nil {
		return false, err
	}
	a, err := hex.DecodeString(mac)
	if err != nil {
		return false, err
	}
	b, err := hex.DecodeString(expected)
	if err != nil {
		return false, err
	}
	if len(a) != len(b) {
		return false, nil
	}
	return hmac.Equal(a, b), nil
}
