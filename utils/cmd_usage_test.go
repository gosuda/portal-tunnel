package utils

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteFlagDefaultsListsRegisteredFlags(t *testing.T) {
	var buf bytes.Buffer
	var identityPath string
	fs := NewFlagSet("expose", nil)
	StringFlagEnv(fs, &identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")

	WriteCommandUsage(&buf, []string{"portal expose [flags] <target>"}, []string{"portal expose 3000"})
	WriteFlagDefaults(&buf, fs)

	got := buf.String()
	for _, want := range []string{"Usage:", "Examples:", "Flags:", "-identity-path", "IDENTITY_PATH"} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q\n%s", want, got)
		}
	}
}

func TestWriteFlagDefaultsNilIsNoop(t *testing.T) {
	WriteFlagDefaults(nil, nil)
	var buf bytes.Buffer
	WriteFlagDefaults(&buf, nil)
	if buf.Len() != 0 {
		t.Fatalf("nil FlagSet should print nothing, got %q", buf.String())
	}
}
