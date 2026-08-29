package sign

import "testing"

func TestEd25519SignAndVerify(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Ed25519("hello world", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(sig, []byte("hello world"), pub) {
		t.Error("signature should be valid")
	}
	if Verify(sig, []byte("other"), pub) {
		t.Error("signature should be invalid for a different message")
	}
}
