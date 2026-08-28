package utils

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteFlagDefaultsListsRegisteredFlags(t *testing.T) {
	ResetEnvRegistry()
	t.Cleanup(ResetEnvRegistry)
	t.Setenv("IDENTITY_PATH", "/private/runtime/identity.json")
	t.Setenv("ADMIN_TOKEN", "admin-token-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-access-key")

	var buf bytes.Buffer
	var identityPath string
	var adminToken string
	var awsSecretAccessKey string
	fs := NewFlagSet("expose", nil)
	StringFlagEnv(fs, &identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	StringFlagEnv(fs, &adminToken, "admin-token", "", "admin bearer token", "ADMIN_TOKEN")
	StringFlagEnv(fs, &awsSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key", "AWS_SECRET_ACCESS_KEY")
	if identityPath != "/private/runtime/identity.json" || adminToken != "admin-token-secret" || awsSecretAccessKey != "aws-secret-access-key" {
		t.Fatal("environment values were not resolved into flag targets")
	}

	WriteCommandUsage(&buf, []string{"portal expose [flags] <target>"}, []string{"portal expose 3000"})
	WriteFlagDefaults(&buf, fs)

	got := buf.String()
	for _, want := range []string{"Usage:", "Examples:", "Flags:", "-identity-path", "identity.json", "IDENTITY_PATH"} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q\n%s", want, got)
		}
	}
	for _, secret := range []string{"/private/runtime/identity.json", "admin-token-secret", "aws-secret-access-key"} {
		if strings.Contains(got, secret) {
			t.Fatalf("help contains environment value %q\n%s", secret, got)
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

func TestWriteHelpSectionLoopbackAndReady(t *testing.T) {
	var buf bytes.Buffer
	WriteHelpSection(&buf, "Loopback", []string{
		"portal expose 127.0.0.1:8080 --identity-path /absolute/path/outside/repo/identity.json --relays https://127.0.0.1:4017 --discovery=false",
	})
	WriteHelpSection(&buf, "Ready", []string{
		"After portal expose succeeds, it logs a line starting with: service ready at",
	})
	got := buf.String()
	for _, want := range []string{
		"Loopback:",
		"--identity-path /absolute/path/outside/repo/identity.json",
		"--relays https://127.0.0.1:4017",
		"--discovery=false",
		"Ready:",
		"service ready at",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q\n%s", want, got)
		}
	}
}
