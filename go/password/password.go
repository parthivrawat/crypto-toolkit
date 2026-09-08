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
	"math/bits"
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

	// ErrInvalidLength is returned when a derived key length is not positive.
	ErrInvalidLength = errors.New("length must be a positive integer")
)

// Options controls cost parameters for password hashing and key derivation.
type Options struct {
	Iterations int    // PBKDF2 iteration count
	Time       uint32 // Argon2 time cost
	Memory     uint32 // Argon2 memory cost in KiB
	Threads    uint8  // Argon2 lanes
	DkLen      int    // Output length in bytes
	N          int    // scrypt N (power of two)
	R          int    // scrypt r
	P          int    // scrypt p
	Cost       int    // bcrypt cost
}

func defaultOptions() *Options {
	return &Options{
		Iterations: 100_000,
		Time:       3,
		Memory:     64 * 1024,
		Threads:    4,
		DkLen:      32,
		N:          16384,
		R:          8,
		P:          1,
		Cost:       12,
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
	if opts.Cost == 0 {
		opts.Cost = d.Cost
	}
	return opts
}

func normalizeAlgorithm(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// Hash returns an Argon2id password hash by default.
func Hash(password string) (string, error) {
	return HashWith(password, "argon2id", nil)
}

// HashWith hashes a password with the chosen algorithm and options.
func HashWith(password, algorithm string, opts *Options) (string, error) {
	if algorithm == "" {
		algorithm = "argon2id"
	}
	algorithm = normalizeAlgorithm(algorithm)
	opts = applyDefaults(opts)

	switch algorithm {
	case "argon2id":
		return hashArgon2id(password, opts)
	case "scrypt":
		return hashScrypt(password, opts)
	case "pbkdf2-sha256", "pbkdf2_sha256":
		return hashPBKDF2(password, opts)
	case "bcrypt":
		return hashBcrypt(password, opts)
	default:
		return "", fmt.Errorf("unsupported password algorithm: %s", algorithm)
	}
}

func hashArgon2id(password string, opts *Options) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, opts.Time, opts.Memory, opts.Threads, uint32(opts.DkLen))
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		opts.Memory, opts.Time, opts.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func hashScrypt(password string, opts *Options) (string, error) {
	if opts.N <= 0 || (opts.N&(opts.N-1)) != 0 {
		return "", errors.New("scrypt N must be a positive power of two")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, opts.N, opts.R, opts.P, opts.DkLen)
	if err != nil {
		return "", err
	}
	ln := bits.Len64(uint64(opts.N)) - 1
	return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s",
		ln, opts.R, opts.P,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func hashPBKDF2(password string, opts *Options) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), salt, opts.Iterations, opts.DkLen, sha256.New)
	return fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s",
		opts.Iterations,
		ab64Encode(salt),
		ab64Encode(key)), nil
}

func hashBcrypt(password string, opts *Options) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), opts.Cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Verify checks a password against a stored hash.
func Verify(password, hashed string) (bool, error) {
	switch {
	case strings.HasPrefix(hashed, "$argon2id$"):
		return verifyArgon2id(password, hashed)
	case strings.HasPrefix(hashed, "$scrypt$"):
		return verifyScrypt(password, hashed)
	case strings.HasPrefix(hashed, "$pbkdf2-sha256$"):
		return verifyPBKDF2(password, hashed)
	case strings.HasPrefix(hashed, "$2a$") || strings.HasPrefix(hashed, "$2b$") || strings.HasPrefix(hashed, "$2y$"):
		err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
		return err == nil, nil
	default:
		return false, ErrInvalidHash
	}
}

func verifyArgon2id(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHash
	}
	params, err := parseParams(parts[2])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	stored, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	if len(salt) == 0 || len(stored) == 0 {
		return false, ErrInvalidHash
	}
	memory, err := parseUintParam(params, "m")
	if err != nil {
		return false, err
	}
	time, err := parseUintParam(params, "t")
	if err != nil {
		return false, err
	}
	threads, err := parseUintParam(params, "p")
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), uint32(len(stored)))
	if len(key) != len(stored) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

func verifyScrypt(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHash
	}
	params, err := parseParams(parts[2])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	stored, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	if len(salt) == 0 || len(stored) == 0 {
		return false, ErrInvalidHash
	}
	ln, err := parseIntParam(params, "ln")
	if err != nil {
		return false, err
	}
	r, err := parseIntParam(params, "r")
	if err != nil {
		return false, err
	}
	p, err := parseIntParam(params, "p")
	if err != nil {
		return false, err
	}
	key, err := scrypt.Key([]byte(password), salt, 1<<ln, r, p, len(stored))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

func verifyPBKDF2(password, hashed string) (bool, error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHash
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, err
	}
	salt, err := ab64Decode(parts[3])
	if err != nil {
		return false, err
	}
	stored, err := ab64Decode(parts[4])
	if err != nil {
		return false, err
	}
	if len(salt) == 0 || len(stored) == 0 {
		return false, ErrInvalidHash
	}
	key := pbkdf2.Key([]byte(password), salt, iterations, len(stored), sha256.New)
	return subtle.ConstantTimeCompare(key, stored) == 1, nil
}

// Derive returns a key derived from passphrase and salt using algorithm.
// If no algorithm is provided, PBKDF2-SHA256 is used.
func Derive(passphrase string, salt []byte, length int, algorithm string, opts *Options) ([]byte, error) {
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	if length <= 0 {
		return nil, ErrInvalidLength
	}

	if algorithm == "" {
		algorithm = "pbkdf2_sha256"
	}
	algorithm = normalizeAlgorithm(algorithm)
	opts = applyDefaults(opts)

	switch algorithm {
	case "pbkdf2-sha256", "pbkdf2_sha256":
		return pbkdf2.Key([]byte(passphrase), salt, opts.Iterations, length, sha256.New), nil
	case "scrypt":
		return scrypt.Key([]byte(passphrase), salt, opts.N, opts.R, opts.P, length)
	case "argon2id":
		return argon2.IDKey([]byte(passphrase), salt, opts.Time, opts.Memory, opts.Threads, uint32(length)), nil
	default:
		return nil, fmt.Errorf("unsupported key derivation algorithm: %s", algorithm)
	}
}

// --- helpers ---

func ab64Encode(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)
	s = strings.ReplaceAll(s, "+", ".")
	return strings.TrimRight(s, "=")
}

func ab64Decode(text string) ([]byte, error) {
	s := strings.ReplaceAll(text, ".", "+")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ",")
	params := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, ErrInvalidHash
		}
		params[kv[0]] = kv[1]
	}
	return params, nil
}

func parseUintParam(params map[string]string, key string) (uint32, error) {
	v, ok := params[key]
	if !ok {
		return 0, ErrInvalidHash
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, ErrInvalidHash
	}
	return uint32(n), nil
}

func parseIntParam(params map[string]string, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, ErrInvalidHash
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, ErrInvalidHash
	}
	return n, nil
}


