package sdk

import "testing"

func TestIdentityPersistenceRoundTrip(t *testing.T) {
	generated, err := GenerateIdentity("sdk-test")
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	data, err := MarshalIdentity(generated)
	if err != nil {
		t.Fatalf("MarshalIdentity() error = %v", err)
	}
	parsed, err := ParseIdentity(data)
	if err != nil {
		t.Fatalf("ParseIdentity() error = %v", err)
	}
	if parsed.Name != generated.Name || parsed.Address != generated.Address || parsed.PublicKey != generated.PublicKey || parsed.PrivateKey != generated.PrivateKey {
		t.Fatal("ParseIdentity() did not preserve the generated identity")
	}
}
