package types

import (
	"strings"
	"testing"
)

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
