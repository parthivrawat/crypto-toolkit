package password

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestHashWithPBKDF2(t *testing.T) {
	h, err := HashWith("user-password", "pbkdf2_sha256", &Options{Iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$pbkdf2-sha256$") {
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

func TestHashWithScrypt(t *testing.T) {
	h, err := HashWith("user-password", "scrypt", &Options{N: 1024, R: 8, P: 1, DkLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$scrypt$") {
		t.Fatalf("unexpected hash prefix: %s", h)
	}
	ok, err := Verify("user-password", h)
	if err != nil || !ok {
		t.Errorf("Verify failed: ok=%v err=%v", ok, err)
	}
}

func TestHashRoundTrip(t *testing.T) {
	h, err := Hash("user-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
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

func TestVerifyBcrypt2y(t *testing.T) {
	h, err := HashWith("user-password", "bcrypt", &Options{Cost: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Hashes produced by other bcrypt implementations commonly use $2y$.
	if !strings.HasPrefix(h, "$2") {
		t.Fatalf("unexpected bcrypt prefix: %s", h[:4])
	}
	h2y := "$2y$" + h[4:]
	ok, err := Verify("user-password", h2y)
	if err != nil || !ok {
		t.Errorf("Verify failed for $2y$ hash: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify("wrong", h2y)
	if ok {
		t.Error("Verify should fail for wrong password against $2y$ hash")
	}
}

func TestDerive(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	key, err := Derive("passphrase", salt, 32, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
	key2, err := Derive("passphrase", salt, 32, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, key2) {
		t.Error("derived key is not deterministic")
	}
}

func TestDeriveRequiresSalt(t *testing.T) {
	if _, err := Derive("passphrase", nil, 32, "", nil); !errors.Is(err, ErrEmptySalt) {
		t.Errorf("expected ErrEmptySalt for nil salt, got %v", err)
	}
	if _, err := Derive("passphrase", []byte{}, 32, "", nil); !errors.Is(err, ErrEmptySalt) {
		t.Errorf("expected ErrEmptySalt for empty salt, got %v", err)
	}
	if _, err := Derive("passphrase", []byte("salt"), 0, "", nil); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("expected ErrInvalidLength for zero length, got %v", err)
	}
}

// TestVerifyMalformedHashes ensures no malformed input ever verifies.
// Numeric cost parameters are kept small or non-numeric so verification
// fails during parsing rather than attempting a huge allocation.
func TestVerifyMalformedHashes(t *testing.T) {
	malformed := []string{
		// Unrecognized formats -> ErrInvalidHash
		"notahash",
		"",
		"garbage",
		"$unknown$stuff",
		// bcrypt-family garbage -> compare fails, never true
		"$2y$garbage",
		"$2a$garbage",
		"$2b$garbage",
		"$2y$10$abcdefghijklmnopqrstuv",
		// argon2id malformed variants
		"$argon2id$garbage",
		"$argon2id$v=19$m=8,t=1,p=1$short",
		"$argon2id$m=8,t=1,p=1$c2FsdA$aGFzaA", // valid format, wrong key
		"$argon2id$v=19$m=abc,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$t=1,p=1$c2FsdA$aGFzaA", // missing m
		"$argon2id$v=19$m=8,t=1$c2FsdA$aGFzaA", // missing p
		"$argon2id$v=19$m=8,t=1,p=1$!!!notbase64!!!$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$!!!notbase64!!!",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA$extra",
		"$argon2id$v=19$badparams$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1$$",     // empty salt and digest
		"$argon2id$v=19$m=8,t=1,p=1$$aGFzaA", // empty salt
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$", // empty digest
		// scrypt malformed variants
		"$scrypt$garbage",
		"$scrypt$ln=abc,r=8,p=1$c2FsdA$aGFzaA",
		"$scrypt$ln=4,r=8$c2FsdA$aGFzaA", // missing p
		"$scrypt$ln=4,r=8,p=1$!!!notbase64!!!$aGFzaA",
		"$scrypt$ln=4,r=8,p=1$c2FsdA$!!!notbase64!!!",
		"$scrypt$ln=4,r=8,p=1$c2FsdA$aGFzaA$extra",
		"$scrypt$ln=4,r=x,p=1$c2FsdA$aGFzaA",
		"$scrypt$ln=4,r=8,p=1$c2FsdA$aGFzaA",
		"$scrypt$ln=4,r=8,p=1$$",     // empty salt and digest
		"$scrypt$ln=4,r=8,p=1$$aGFzaA", // empty salt
		"$scrypt$ln=4,r=8,p=1$c2FsdA$", // empty digest
		// pbkdf2 malformed variants
		"$pbkdf2-sha256$garbage",
		"$pbkdf2-sha256$abc$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$1000$!!!notbase64!!!$aGFzaA",
		"$pbkdf2-sha256$1000$c2FsdA$!!!notbase64!!!",
		"$pbkdf2-sha256$1000$c2FsdA$aGFzaA$extra",
		"$pbkdf2-sha256$1$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$10$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$100$$",     // empty salt and digest
		"$pbkdf2-sha256$100$$aGFzaA", // empty salt
		"$pbkdf2-sha256$100$c2FsdA$", // empty digest
	}
	for _, h := range malformed {
		ok, err := Verify("cross-language-test", h)
		if ok {
			t.Errorf("Verify returned true for malformed hash %q", h)
		}
		// Unknown prefixes must surface ErrInvalidHash.
		switch {
		case h == "notahash", h == "", h == "garbage", h == "$unknown$stuff":
			if !errors.Is(err, ErrInvalidHash) {
				t.Errorf("Verify(%q): expected ErrInvalidHash, got %v", h, err)
			}
		}
	}
}

func TestDeriveCustomIterations(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	k1, err := Derive("passphrase", salt, 32, "pbkdf2_sha256", &Options{Iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Derive("passphrase", salt, 32, "pbkdf2_sha256", &Options{Iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("derived keys do not match")
	}
}

func TestDeriveScryptCustomParams(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	k1, err := Derive("passphrase", salt, 32, "scrypt", &Options{N: 1024, R: 8, P: 1})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Derive("passphrase", salt, 32, "scrypt", &Options{N: 1024, R: 8, P: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("derived scrypt keys do not match")
	}
}
