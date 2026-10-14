package utils

import (
	"slices"
	"testing"
)

func TestParseFlagSetPreservesEndOfOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		wantArgs []string
		wantName string
	}{
		{
			name:     "flag-like target after terminator",
			args:     []string{"--", "--serve=."},
			wantArgs: []string{"--serve=."},
		},
		{
			name:     "flag-like target after named option",
			args:     []string{"--name", "demo", "--", "--serve=."},
			wantArgs: []string{"--serve=."},
			wantName: "demo",
		},
		{
			name:     "earlier positional remains positional",
			args:     []string{"localhost:3000", "--name", "demo", "--", "--serve=."},
			wantArgs: []string{"localhost:3000", "--serve=."},
			wantName: "demo",
		},
		{
			name:     "flags after terminator remain positional",
			args:     []string{"--", "localhost:3000", "--name", "demo"},
			wantArgs: []string{"localhost:3000", "--name", "demo"},
		},
		{
			name:     "existing interspersed flags keep working",
			args:     []string{"localhost:3000", "--name", "demo"},
			wantArgs: []string{"localhost:3000"},
			wantName: "demo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fs := NewFlagSet("expose", nil)
			var name, serve string
			fs.StringVar(&name, "name", "", "")
			fs.StringVar(&serve, "serve", "", "")
			if err := ParseFlagSet(fs, tt.args, nil); err != nil {
				t.Fatalf("ParseFlagSet() error = %v", err)
			}
			if !slices.Equal(fs.Args(), tt.wantArgs) {
				t.Errorf("args = %q, want %q", fs.Args(), tt.wantArgs)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if serve != "" {
				t.Errorf("serve = %q, want empty: positional option was parsed", serve)
			}
		})
	}
}
