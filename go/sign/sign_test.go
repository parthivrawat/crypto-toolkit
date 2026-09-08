package sign

import (
	"encoding/hex"
	"testing"
)

func TestEd25519SignAndVerify(t *testing.T) {
	seed, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Ed25519("hello world", seed)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(sig, []byte("hello world"), pub)
	if err != nil || !ok {
		t.Errorf("signature should be valid: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify(sig, []byte("other"), pub)
	if ok {
		t.Error("signature should be invalid for a different message")
	}
}

// TestEd25519CrossLanguageVector verifies a deterministic signature shared
// with the other language implementations of this toolkit.
func TestEd25519CrossLanguageVector(t *testing.T) {
	seed, err := hex.DecodeString("d177524e40ee195afe206345792e20c8117c8254f2ce98ee45589625f89fc4b8")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString("a3b599b8cef3428956452bf75a445860958633aa3bf0c4160a09e6c0fcba2463")
	if err != nil {
		t.Fatal(err)
	}
	wantSig, err := hex.DecodeString("8b0dd73d7644c49c208398874ce6cdfc98a49a7c05fc613dc5be9382c10bbdd43da9466d6f10646c72d9d5adea33e8f15c3349fab5478d58400fcf93db0f0b09")
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 is deterministic: signing must reproduce the vector exactly.
	sig, err := Ed25519("cross-language-test", seed)
	if err != nil {
		t.Fatal(err)
	}
	if !areEqual(sig, wantSig) {
		t.Fatalf("signature mismatch:\n got %x\nwant %x", sig, wantSig)
	}

	ok, err := Verify(sig, []byte("cross-language-test"), pub)
	if err != nil || !ok {
		t.Fatalf("vector signature should verify: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify(sig, []byte("cross-language-tesT"), pub)
	if ok {
		t.Error("vector signature should not verify for a different message")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	seed, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pemSk, err := PrivateKeyToPEM(seed)
	if err != nil {
		t.Fatal(err)
	}
	pemPk, err := PublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	loadedSeed, err := PrivateKeyFromPEM(pemSk)
	if err != nil {
		t.Fatal(err)
	}
	loadedPub, err := PublicKeyFromPEM(pemPk)
	if err != nil {
		t.Fatal(err)
	}
	if !areEqual(seed, loadedSeed) {
		t.Error("seed round trip failed")
	}
	if !areEqual(pub, loadedPub) {
		t.Error("public key round trip failed")
	}
}

func areEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
