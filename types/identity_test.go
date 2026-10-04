package types

import "testing"

func TestServiceIdentityKeySerializationBoundary(t *testing.T) {
	t.Parallel()

	key := NewServiceIdentityKey(" Demo ", " 0xAbCd ")
	if got := key.String(); got != "demo:0xabcd" {
		t.Fatalf("ServiceIdentityKey.String() = %q, want demo:0xabcd", got)
	}
	parsed, err := ParseServiceIdentityKey(" Demo : 0xAbCd ")
	if err != nil {
		t.Fatal(err)
	}
	if parsed != key {
		t.Fatalf("ParseServiceIdentityKey() = %#v, want %#v", parsed, key)
	}
	if got, err := ParseIdentityKey(" Demo : 0xAbCd "); err != nil || got != key.String() {
		t.Fatalf("ParseIdentityKey() = %q, %v, want %q", got, err, key.String())
	}
}

func TestServiceIdentityKeyRejectsMalformedSerialization(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "demo", ":0x1", "demo:", "demo:0x1:extra"} {
		if _, err := ParseServiceIdentityKey(raw); err == nil {
			t.Errorf("ParseServiceIdentityKey(%q) error = nil", raw)
		}
	}
}
