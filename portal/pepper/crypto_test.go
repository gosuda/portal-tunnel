package pepper

import "testing"

func TestHKDFLabelsAreDomainSeparated(t *testing.T) {
	t.Parallel()

	secret := []byte("secret")
	salt := []byte("salt")
	a, err := DeriveKey(secret, salt, LabelE2EBundle, 32)
	if err != nil {
		t.Fatalf("derive e2e key: %v", err)
	}
	b, err := DeriveKey(secret, salt, LabelOnionHop, 32)
	if err != nil {
		t.Fatalf("derive onion key: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("expected different labels to derive different keys")
	}
}

func TestAEADDecryptFailsOnTamperedCiphertext(t *testing.T) {
	t.Parallel()

	aead, err := NewE2EBundleAEAD([]byte("secret"), []byte("salt"))
	if err != nil {
		t.Fatalf("new aead: %v", err)
	}
	ciphertext, nonce, err := aead.Seal([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	ciphertext[0] ^= 0xFF
	if _, err := aead.Open(ciphertext, nonce, []byte("aad")); err == nil {
		t.Fatal("expected tampered ciphertext to fail decryption")
	}
}
