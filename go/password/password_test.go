package password

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashWithPBKDF2(t *testing.T) {
	h, err := HashWith("user-password", "pbkdf2_sha256", &Options{Iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2_sha256$") {
		t.Fatalf("unexpected hash prefix: %s", h)
	}

	ok, err := Verify("user-password", h)
	if err != nil || !ok {
		t.Errorf("Verify failed: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify("wrong", h)
	if ok {
		t.Error("Verify should fail for wrong password")
	}
}

func TestDerive(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	key, err := Derive("passphrase", salt, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
	key2, err := Derive("passphrase", salt, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, key2) {
		t.Error("derived key is not deterministic")
	}
}

func TestDeriveRequiresSalt(t *testing.T) {
	if _, err := Derive("passphrase", nil, 32); err == nil {
		t.Error("expected error for empty salt")
	}
}
