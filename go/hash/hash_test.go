package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestString(t *testing.T) {
	got, err := String("hello world", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(sha256.New().Sum([]byte("hello world")))
	// sha256.New().Sum appends to provided slice; reset to get correct value.
	h := sha256.New()
	h.Write([]byte("hello world"))
	want = hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringRejectsWeak(t *testing.T) {
	if _, err := String("test", "md5"); err == nil {
		t.Error("expected error for md5")
	}
	if _, err := String("test", "sha-1"); err == nil {
		t.Error("expected error for sha-1")
	}
}

func TestHMAC(t *testing.T) {
	mac, err := HMAC("key", "message", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyHMAC(mac, "key", "message", "sha-256"); !ok {
		t.Error("VerifyHMAC should succeed for matching HMAC")
	}
	if ok, _ := VerifyHMAC(mac, "key", "tampered", "sha-256"); ok {
		t.Error("VerifyHMAC should fail for tampered data")
	}
}
