package types

import (
	"strings"
	"testing"
)

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

	unnamedKey := NewServiceIdentityKey("", " 0xAbCd ")
	if got := unnamedKey.String(); got != ":0xabcd" {
		t.Fatalf("unnamed ServiceIdentityKey.String() = %q, want :0xabcd", got)
	}
	parsedUnnamed, err := ParseServiceIdentityKey(" : 0xAbCd ")
	if err != nil {
		t.Fatal(err)
	}
	if parsedUnnamed != unnamedKey {
		t.Fatalf("ParseServiceIdentityKey() = %#v, want %#v", parsedUnnamed, unnamedKey)
	}
	if got, err := ParseIdentityKey(" : 0xAbCd "); err != nil || got != unnamedKey.String() {
		t.Fatalf("ParseIdentityKey() = %q, %v, want %q", got, err, unnamedKey.String())
	}
}

func TestServiceIdentityKeyRejectsMalformedSerialization(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "demo", ":", "demo:", "demo:0x1:extra", ":0x1:extra"} {
		if _, err := ParseServiceIdentityKey(raw); err == nil {
			t.Errorf("ParseServiceIdentityKey(%q) error = nil", raw)
		}
	}
}

func TestLeaseMetadataValidate(t *testing.T) {
	tags := make([]string, 14)
	for i := range tags {
		tags[i] = strings.Repeat("a", 128)
	}
	tests := []struct {
		name     string
		metadata LeaseMetadata
		valid    bool
	}{
		{"empty", LeaseMetadata{}, true},
		{"maximum description", LeaseMetadata{Description: strings.Repeat("a", 4096)}, true},
		{"description too long", LeaseMetadata{Description: strings.Repeat("a", 4097)}, false},
		{"owner too long", LeaseMetadata{Owner: strings.Repeat("a", 257)}, false},
		{"thumbnail too long", LeaseMetadata{Thumbnail: strings.Repeat("a", 2049)}, false},
		{"too many tags", LeaseMetadata{Tags: make([]string, 33)}, false},
		{"tag too long", LeaseMetadata{Tags: []string{strings.Repeat("a", 129)}}, false},
		{"aggregate at limit", LeaseMetadata{Description: strings.Repeat("a", 4096), Thumbnail: strings.Repeat("a", 2048), Tags: tags, Owner: strings.Repeat("a", 256)}, true},
		{"aggregate too large", LeaseMetadata{Description: strings.Repeat("a", 4096), Thumbnail: strings.Repeat("a", 2048), Tags: append(append([]string(nil), tags...), "a"), Owner: strings.Repeat("a", 256)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.metadata.Validate() == nil; got != tt.valid {
				t.Fatalf("Validate() success = %t, want %t", got, tt.valid)
			}
		})
	}
}
