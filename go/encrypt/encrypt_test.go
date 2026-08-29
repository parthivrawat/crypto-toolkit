package encrypt

import (
	"bytes"
	"testing"
)

func TestAESGCMRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x78}, 32)
	ct, err := SymmetricString("sensitive data", key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptString(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "sensitive data" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestChaCha20Poly1305Roundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 32)
	ct, err := SymmetricStringWith("sensitive data", key, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptString(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "sensitive data" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestTamperingRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	ct, err := SymmetricString("data", key)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := Decrypt(ct, key); err == nil {
		t.Error("expected decryption to fail for tampered ciphertext")
	}
}
