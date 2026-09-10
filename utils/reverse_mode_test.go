package utils

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNormalizeReverseMode(t *testing.T) {
	tests := map[types.ReverseMode]types.ReverseMode{
		"":          types.ReverseModeAuto,
		" AUTO ":    types.ReverseModeAuto,
		"DIRECT":    types.ReverseModeDirect,
		" overlay ": types.ReverseModeOverlay,
	}
	for input, want := range tests {
		got, err := NormalizeReverseMode(input)
		if err != nil || got != want {
			t.Errorf("NormalizeReverseMode(%q) = %q, %v, want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeReverseMode("invalid"); err == nil {
		t.Fatal("NormalizeReverseMode(invalid) error = nil")
	}
}
