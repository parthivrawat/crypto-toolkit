package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestString(t *testing.T) {
	got, err := String("hello world", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("hello world"))
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringRejectsWeak(t *testing.T) {
	for _, alg := range []string{"md5", "sha-1", "sha1", "SHA1", "MD5", "not-a-hash"} {
		if _, err := String("test", alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("String(_, %q): expected ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
}

func TestFileRejectsWeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.bin")
	for _, alg := range []string{"md5", "sha-1", "sha1", "not-a-hash"} {
		if _, err := File(path, alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("File(_, %q): expected ErrUnsupportedAlgorithm, got %v", alg, err)
		}
	}
}

func TestHMACRejectsWeak(t *testing.T) {
	for _, alg := range []string{"md5", "sha-1", "sha1", "not-a-hash"} {
		if _, err := HMAC("key", "data", alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("HMAC(_, _, %q): expected ErrUnsupportedAlgorithm, got %v", alg, err)
		}
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

// TestCrossLanguageVectors verifies exact outputs shared with the other
// language implementations of this toolkit.
func TestCrossLanguageVectors(t *testing.T) {
	got, err := String("cross-language-test", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	const wantSHA256 = "8de4271480b58aedac9d059165faa03bf42062f77ae9196f0932f2ab9994c96e"
	if got != wantSHA256 {
		t.Errorf("String() = %q, want %q", got, wantSHA256)
	}

	mac, err := HMAC("cross-language-key", "cross-language-test", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	const wantHMAC = "9d67f44518758c0e736fa7961cbe9d5f5bd2dde2ee85867b01b7e9cbfdb8e4c5"
	if mac != wantHMAC {
		t.Errorf("HMAC() = %q, want %q", mac, wantHMAC)
	}
}

func TestStringEmpty(t *testing.T) {
	got, err := String("", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(sha256.New().Sum(nil))
	if got != want {
		t.Errorf("String(\"\") = %q, want %q", got, want)
	}
}

func TestFileLarge(t *testing.T) {
	// ~5MB of deterministic bytes.
	content := make([]byte, 5*1024*1024)
	for i := range content {
		content[i] = byte(i % 251)
	}
	path := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := File(path, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("File() = %q, want %q", got, want)
	}
}

func TestVerifyHMACMalformedInput(t *testing.T) {
	valid, err := HMAC("key", "data", "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	// Non-hex mac must return false (and an error).
	if ok, _ := VerifyHMAC("zzzz-not-hex", "key", "data", "sha-256"); ok {
		t.Error("VerifyHMAC should return false for non-hex mac")
	}
	// Wrong-length (but valid hex) mac must return false.
	if ok, err := VerifyHMAC("00", "key", "data", "sha-256"); ok || err != nil {
		t.Errorf("VerifyHMAC short mac: ok=%v err=%v, want false, nil", ok, err)
	}
	// Truncated valid mac must return false.
	if ok, err := VerifyHMAC(valid[:len(valid)-2], "key", "data", "sha-256"); ok || err != nil {
		t.Errorf("VerifyHMAC truncated mac: ok=%v err=%v, want false, nil", ok, err)
	}
}
