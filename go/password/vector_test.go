package password

import (
	"encoding/hex"
	"testing"
)

const (
	pbkdf2Vector = "$pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$NQw0IIbZMo3k82KG1TAVtju63YeHXZMliByZZ4DKD9o"
	scryptVector = "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHQ$KXXf8GmVmUQTGZ9L0BWzp7rywGFqGVKQ+kazyyuoqFM"
)

func TestVerifyCrossLanguagePBKDF2Vector(t *testing.T) {
	ok, err := Verify("cross-language-test", pbkdf2Vector)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected PBKDF2 vector to verify")
	}
}

func TestVerifyCrossLanguageScryptVector(t *testing.T) {
	ok, err := Verify("cross-language-test", scryptVector)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected scrypt vector to verify")
	}
}

func TestVerifyWrongPasswordAgainstVectors(t *testing.T) {
	for _, vector := range []string{pbkdf2Vector, scryptVector} {
		ok, _ := Verify("wrong-password", vector)
		if ok {
			t.Fatalf("expected %s to reject wrong password", vector)
		}
	}
}

// TestDeriveCrossLanguageVectors verifies exact derived-key outputs shared
// with the other language implementations of this toolkit.
func TestDeriveCrossLanguageVectors(t *testing.T) {
	salt := []byte("saltsaltsaltsaltsaltsaltsaltsalt") // 32 bytes
	vectors := []struct {
		name      string
		algorithm string
		opts      *Options
		wantHex   string
	}{
		{
			name:      "pbkdf2_sha256",
			algorithm: "pbkdf2_sha256",
			opts:      &Options{Iterations: 1000},
			wantHex:   "350c342086d9328de4f36286d53015b63bbadd87875d9325881c996780ca0fda",
		},
		{
			name:      "scrypt",
			algorithm: "scrypt",
			opts:      &Options{N: 1024, R: 8, P: 1},
			wantHex:   "2975dff06995994413199f4bd015b3a7baf2c0616a195290fa46b3cb2ba8a853",
		},
		{
			name:      "argon2id",
			algorithm: "argon2id",
			opts:      &Options{Time: 3, Memory: 65536, Threads: 4},
			wantHex:   "4495c94ca3852576fa10b1ee381c3742f7aaf152499bd42be93b59427fca331c",
		},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key, err := Derive("cross-language-test", salt, 32, v.algorithm, v.opts)
			if err != nil {
				t.Fatalf("Derive() error: %v", err)
			}
			if got := hex.EncodeToString(key); got != v.wantHex {
				t.Errorf("Derive() = %q, want %q", got, v.wantHex)
			}
		})
	}
}
