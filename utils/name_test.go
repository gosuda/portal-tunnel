package utils

import "testing"

func TestDefaultExposeName(t *testing.T) {
	t.Parallel()

	// Cross-language parity vectors -- keep in sync with frontend/src/lib/exposeName.test.ts
	tests := []struct {
		target string
		seed   string
		want   string
	}{
		{target: "3000", seed: "test_seed", want: "bubble-cricket-beacon"},
		{target: "", seed: "portal", want: "zesty-beacon-sketch"},
		{target: "http://localhost:8080", seed: "cli_abc", want: "sprightly-rocket-zap"},
		{target: "192.168.1.1:8080", seed: "web_xyz", want: "velvet-yeti-march"},
		{target: "localhost", seed: "cli_", want: "misty-rocket-ripple"},
		// sprightly-thimble-boogie would exceed the lease name limit.
		{target: "3000", seed: "test_seed_24", want: "sprightly-thimble"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			got, err := DefaultExposeName(tt.target, tt.seed)
			if err != nil {
				t.Fatalf("DefaultExposeName(%q, %q) error = %v", tt.target, tt.seed, err)
			}
			if got != tt.want {
				t.Fatalf("DefaultExposeName(%q, %q) = %q, want %q", tt.target, tt.seed, got, tt.want)
			}
		})
	}
}
