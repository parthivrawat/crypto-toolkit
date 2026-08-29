// Package password provides password hashing, verification, and key derivation
// using modern algorithms (Argon2id, scrypt, bcrypt, PBKDF2).
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	// ErrEmptySalt is returned when a salt is empty or nil.
	ErrEmptySalt = errors.New("salt must not be empty")

	// ErrInvalidHash is returned when a password hash format is invalid.
	ErrInvalidHash = errors.New("invalid password hash format")
)

// Options controls cost parameters for password hashing.
type Options struct {
	Iterations int
	Time       uint32
	Memory     uint32
	Threads    uint8
	DkLen      int
	N          int
	R          int
	P          int
}

func defaultOptions() *Options {
	return &Options{
		Iterations: 100000,
		Time:       1,
		Memory:     64 * 1024,
		Threads:    4,
		DkLen:      64,
		N:          16384,
		R:          8,
		P:          1,
	}
}

func applyDefaults(opts *Options) *Options {
	d := defaultOptions()
	if opts == nil {
		return d
	}
	if opts.Iterations == 0 {
		opts.Iterations = d.Iterations
	}
	if opts.Time == 0 {
		opts.Time = d.Time
	}
	if opts.Memory == 0 {
		opts.Memory = d.Memory
	}
	if opts.Threads == 0 {
		opts.Threads = d.Threads
	}
	if opts.DkLen == 0 {
		opts.DkLen = d.DkLen
	}
	if opts.N == 0 {
		opts.N = d.N
	}
	if opts.R == 0 {
		opts.R = d.R
	}
	if opts.P == 0 {
		opts.P = d.P
	}
	return opts
}

// Hash returns an Argon2id password hash by default.
func Hash(password string) (string, error) {
	return HashWith(password, "", nil)
}

// HashWith hashes a password with the chosen algorithm and options.
func HashWith(password, algorithm string, opts *Options) (string, error) {
	opts = applyDefaults(opts)
	if algorithm == "" {
		algorithm = "argon2id"
	}

	switch strings.ToLower(algorithm) {
	case "argon2id":
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		key := argon2.IDKey([]byte(password), salt, opts.Time, opts.Memory, opts.Threads, uint32(opts.DkLen))
		return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s",
			opts.Time, opts.Memory, opts.Threads,
			base64.StdEncoding.EncodeToString(salt),
			base64.StdEncoding.EncodeToString(key)), nil
	case "scrypt":
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		key, err := scrypt.Key([]byte(password), salt, opts.N, opts.R, opts.P, opts.DkLen)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s",
			opts.N, opts.R, opts.P,
			base64.StdEncoding.EncodeToString(salt),
			base64.StdEncoding.EncodeToString(key)), nil
	case "bcrypt":
		cost := opts.Iterations
		if cost == 0 {
			cost = bcrypt.DefaultCost
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
		if err != nil {
			return "", err
		}
		return string(h), nil
	case "pbkdf2_sha256":
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		key := pbkdf2.Key([]byte(password), salt, opts.Iterations, opts.DkLen, sha256.New)
		return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
			opts.Iterations,
			base64.StdEncoding.EncodeToString(salt),
			base64.StdEncoding.EncodeToString(key)), nil
	default:
		return "", fmt.Errorf("unsupported password algorithm: %s", algorithm)
	}
}

// Verify checks a password against a stored hash.
func Verify(password, hashed string) (bool, error) {
	switch {
	case strings.HasPrefix(hashed, "argon2id$"):
		return verifyArgon2id(password, hashed)
	case strings.HasPrefix(hashed, "scrypt$"):
		return verifyScrypt(password, hashed)
	case strings.HasPrefix(hashed, "pbkdf2_sha256$"):
		return verifyPBKDF2(password, hashed)
	case strings.HasPrefix(hashed, "$2a$") || strings.HasPrefix(hashed, "$2b$"):
		err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
		return err == nil, nil
	default:
		return false, ErrInvalidHash
	}
}

func verifyArgon2id(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}
	time, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return false, err
	}
	memory, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return false, err
	}
	threads, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return false, err
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	stored, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), salt, uint32(time), uint32(memory), uint8(threads), uint32(len(stored)))
	if len(key) != len(stored) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

func verifyScrypt(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}
	N, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}
	R, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, err
	}
	P, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	stored, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	key, err := scrypt.Key([]byte(password), salt, N, R, P, len(stored))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

func verifyPBKDF2(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 4 {
		return false, ErrInvalidHash
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}
	stored, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(password), salt, iterations, len(stored), sha256.New)
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

// Derive returns a key derived from passphrase and salt using algorithm.
// If no algorithm is provided, PBKDF2-SHA256 is used.
func Derive(passphrase string, salt []byte, length int, algorithm ...string) ([]byte, error) {
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	if length <= 0 {
		return nil, errors.New("length must be a positive integer")
	}

	algo := "pbkdf2_sha256"
	if len(algorithm) > 0 && algorithm[0] != "" {
		algo = algorithm[0]
	}
	opts := defaultOptions()

	switch strings.ToLower(algo) {
	case "pbkdf2_sha256":
		return pbkdf2.Key([]byte(passphrase), salt, opts.Iterations, length, sha256.New), nil
	case "scrypt":
		return scrypt.Key([]byte(passphrase), salt, opts.N, opts.R, opts.P, length)
	default:
		return nil, fmt.Errorf("unsupported key derivation algorithm: %s", algo)
	}
}
