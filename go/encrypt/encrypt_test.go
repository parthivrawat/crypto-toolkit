package encrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand"
	"testing"
)

func TestAESGCMRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x78}, 32)
	ct, err := EncryptString("sensitive data", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != version {
		t.Fatalf("expected version %d, got %d", version, ct[0])
	}
	pt, err := DecryptString(ct, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "sensitive data" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestChaCha20Poly1305Roundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 32)
	ct, err := EncryptStringWith("sensitive data", key, nil, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptString(ct, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "sensitive data" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	aad := []byte("context")
	ct, err := Encrypt([]byte("data"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(ct, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("data")) {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if _, err := Decrypt(ct, key, []byte("wrong")); err == nil {
		t.Error("expected AAD mismatch")
	}
}

func TestTamperingRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	ct, err := EncryptString("data", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := Decrypt(ct, key, nil); err == nil {
		t.Error("expected decryption to fail for tampered ciphertext")
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	for _, alg := range []string{"aes-128-gcm", "md5", "rot13", "not-an-algo"} {
		if _, err := EncryptWith([]byte("data"), key, nil, alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("EncryptWith(_, _, _, %q): expected ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
}

func TestInvalidKeyLength(t *testing.T) {
	for _, alg := range []string{"", "aes-256-gcm", "chacha20-poly1305"} {
		for _, keyLen := range []int{0, 16, 31, 33} {
			key := bytes.Repeat([]byte{0x01}, keyLen)
			if _, err := EncryptWith([]byte("data"), key, nil, alg); !errors.Is(err, ErrInvalidKey) {
				t.Errorf("EncryptWith(_, %d-byte key, _, %q): expected ErrInvalidKey, got %v", keyLen, alg, err)
			}
		}
	}
}

func TestDecryptRejectsMalformedTokens(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)

	if _, err := Decrypt(nil, key, nil); err == nil {
		t.Error("expected error for empty token")
	}
	if _, err := Decrypt([]byte{version}, key, nil); err == nil {
		t.Error("expected error for truncated token")
	}
	if _, err := Decrypt([]byte{99, 1, 0, 0}, key, nil); err == nil {
		t.Error("expected error for unknown version")
	}
	if _, err := Decrypt([]byte{version, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, key, nil); err == nil {
		t.Error("expected error for unknown algorithm id")
	}
}

// TestCrossLanguageVectors decrypts fixed v2 tokens produced by the other
// language implementations of this toolkit.
func TestCrossLanguageVectors(t *testing.T) {
	key, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []struct {
		name     string
		tokenHex string
		aad      []byte
	}{
		{
			name:     "aes-256-gcm",
			tokenHex: "020100007437945cda0539277c709cf7e0fb65ec51a3771fa6d2cba682cb9326194759aa3f8874d8663d3140d81fc020b807aa",
			aad:      nil,
		},
		{
			name:     "chacha20-poly1305",
			tokenHex: "020200008676258015ff452777b5af24cae1327aacf84a42bf66cb5db3160557782b15d330fa33de6b5d7dc9169377c183e30f",
			aad:      nil,
		},
		{
			name:     "aes-256-gcm with aad",
			tokenHex: "0201000e766563746f722d636f6e746578747f436a5f29c8ff2d66c01fe330f582ecb37d3abc041f46ffa88d9eab1639c59d5570e5cbaec07eaa77be7c3ce8ae8b",
			aad:      []byte("vector-context"),
		},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			token, err := hex.DecodeString(v.tokenHex)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := Decrypt(token, key, v.aad)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}
			if string(pt) != "cross-language-test" {
				t.Fatalf("plaintext mismatch: %q", pt)
			}
		})
	}

	// The AAD token must fail with the wrong or missing AAD.
	token, err := hex.DecodeString(vectors[2].tokenHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(token, key, []byte("wrong-context")); err == nil {
		t.Error("expected error decrypting AAD token with wrong AAD")
	}
	if _, err := Decrypt(token, key, nil); err == nil {
		t.Error("expected error decrypting AAD token with nil AAD")
	}
}

// TestDecryptTruncatedTokens ensures every strict prefix of a valid token
// is rejected.
func TestDecryptTruncatedTokens(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, alg := range []string{"aes-256-gcm", "chacha20-poly1305"} {
		token, err := EncryptStringWith("cross-language-test", key, nil, alg)
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < len(token); n++ {
			if _, err := Decrypt(token[:n], key, nil); err == nil {
				t.Errorf("%s: Decrypt succeeded on token truncated to %d bytes", alg, n)
			}
		}
	}
}

// TestDecryptMutatedTokens flips each byte of a valid token and asserts
// mutations in the nonce/ciphertext/tag region are always rejected.
func TestDecryptMutatedTokens(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, alg := range []string{"aes-256-gcm", "chacha20-poly1305"} {
		token, err := EncryptStringWith("cross-language-test", key, nil, alg)
		if err != nil {
			t.Fatal(err)
		}
		// Header layout: version | algoID | aadLen(2) | aad...
		headerLen := 4 + int(binary.BigEndian.Uint16(token[2:4]))
		for i := range token {
			mutated := make([]byte, len(token))
			copy(mutated, token)
			mutated[i] ^= 0xFF
			_, err := Decrypt(mutated, key, nil)
			if i >= headerLen && err == nil {
				t.Errorf("%s: Decrypt succeeded after mutating byte %d (nonce/ciphertext/tag region)", alg, i)
			}
		}
	}
}

// TestDecryptRandomTokens feeds deterministic pseudo-random garbage to
// Decrypt; none may authenticate or cause a panic.
func TestDecryptRandomTokens(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	rng := rand.New(rand.NewSource(0xdeadbeef))
	for i := 0; i < 500; i++ {
		n := rng.Intn(80)
		buf := make([]byte, n)
		rng.Read(buf)
		// Bias some inputs toward plausible headers.
		if n >= 2 && rng.Intn(2) == 0 {
			buf[0] = byte(rng.Intn(4))
			buf[1] = byte(rng.Intn(4))
		}
		if _, err := Decrypt(buf, key, nil); err == nil {
			t.Fatalf("Decrypt succeeded on random token %d: %x", i, buf)
		}
	}
}

func TestEmptyPlaintextRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, alg := range []string{"aes-256-gcm", "chacha20-poly1305"} {
		token, err := EncryptWith([]byte{}, key, nil, alg)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt(token, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(pt) != 0 {
			t.Errorf("%s: expected empty plaintext, got %x", alg, pt)
		}
	}
}

func TestBinaryPlaintextRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	// Non-UTF-8 binary plaintext.
	plaintext := []byte{0xff, 0xfe, 0x00, 0x01, 0x80, 0x7f, 0xd5, 0x00}
	for _, alg := range []string{"aes-256-gcm", "chacha20-poly1305"} {
		token, err := EncryptWith(plaintext, key, nil, alg)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt(token, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Errorf("%s: binary plaintext mismatch: %x", alg, pt)
		}
	}
}

func TestZeroLengthKeyRejected(t *testing.T) {
	if _, err := Encrypt([]byte("data"), []byte{}, nil); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for zero-length key, got %v", err)
	}
	if _, err := Encrypt([]byte("data"), nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for nil key, got %v", err)
	}
}
