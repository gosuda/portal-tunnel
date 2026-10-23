package main

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// exposeSpec follows portal expose from its arguments to the tunnel spec, the
// way runExposeCommand does before it starts the tunnel.
func exposeSpec(t *testing.T, args ...string) (tunnel.Spec, error) {
	t.Helper()
	var flags exposeFlags
	fs := utils.NewFlagSet("expose", printExposeUsage)
	registerExposeFlags(fs, &flags)
	if err := utils.ParseFlagSet(fs, args, printExposeUsage); err != nil {
		t.Fatalf("parse portal expose %v: %v", args, err)
	}
	flags.targetAddr = fs.Arg(0)
	spec, err := tunnelSpecFromExposeFlags(fs, flags)
	if err != nil {
		return spec, err
	}
	return spec, spec.Validate()
}

func setOIDCEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("AUTH_OIDC_CLIENT_ID", "client-id")
	t.Setenv("AUTH_OIDC_CLIENT_SECRET", "client-secret")
}

// AUTH_OIDC_* may be exported for a single service, so they must neither turn
// application auth on for every other portal expose nor make another provider
// fail validation.
func TestExposeIgnoresOIDCEnvWithoutAuthOIDC(t *testing.T) {
	setOIDCEnv(t)

	for _, args := range [][]string{{"3000"}, {"--tcp", "3000"}, {"--auth", "siwe", "3000"}, {"--auth", "credential", "3000"}} {
		spec, err := exposeSpec(t, args...)
		if err != nil {
			t.Errorf("portal expose %v: %v", args, err)
			continue
		}
		if spec.HTTP == nil || spec.HTTP.Auth == nil {
			continue
		}
		if auth := spec.HTTP.Auth; auth.OIDCIssuerURL != "" || auth.OIDCClientID != "" {
			t.Errorf("portal expose %v carried AUTH_OIDC_* into %+v", args, auth)
		}
	}
	if spec, _ := exposeSpec(t, "3000"); spec.HTTP != nil {
		t.Errorf("AUTH_OIDC_* alone enabled HTTP handling: %+v", spec.HTTP)
	}
}

func TestExposeAuthOIDCReadsEnv(t *testing.T) {
	setOIDCEnv(t)

	spec, err := exposeSpec(t, "--auth", "OIDC", "--auth-allow", "alice@example.com", "3000")
	if err != nil {
		t.Fatal(err)
	}
	auth := spec.HTTP.Auth
	if auth.OIDCIssuerURL != "https://issuer.example.com" || auth.OIDCClientID != "client-id" || auth.OIDCClientSecret != "client-secret" {
		t.Fatalf("--auth oidc config = %+v, want the AUTH_OIDC_* values", auth)
	}
}

// A flag typed on the command line is deliberate: without --auth oidc it must
// still be refused instead of starting a tunnel the operator believes is protected.
func TestExposeRefusesExplicitOIDCFlagWithoutAuthOIDC(t *testing.T) {
	for _, args := range [][]string{
		{"--auth-oidc-issuer", "https://issuer.example.com", "3000"},
		{"--auth", "siwe", "--auth-oidc-client-id", "client-id", "3000"},
	} {
		if _, err := exposeSpec(t, args...); err == nil {
			t.Errorf("portal expose %v started without --auth oidc", args)
		}
	}
}

const identityProofEnv = "test-proof-0123456789"

// AUTH_IDENTITY_PROOF may be exported for one service, so without
// --auth-identity-headers it must neither turn application auth on for every
// other portal expose nor make a protected one fail validation.
func TestExposeIgnoresIdentityProofEnvWithoutIdentityHeaders(t *testing.T) {
	t.Setenv("AUTH_IDENTITY_PROOF", identityProofEnv)

	spec, err := exposeSpec(t, "3000")
	if err != nil || spec.HTTP != nil {
		t.Fatalf("portal expose 3000 with AUTH_IDENTITY_PROOF = %+v, %v; want a plain tunnel", spec.HTTP, err)
	}
	spec, err = exposeSpec(t, "--auth", "siwe", "3000")
	if err != nil || spec.HTTP.Auth.IdentityProof != "" {
		t.Fatalf("portal expose --auth siwe with AUTH_IDENTITY_PROOF = %+v, %v; want the proof dropped", spec.HTTP.Auth, err)
	}
}

func TestExposeIdentityProofReadsEnvWithIdentityHeaders(t *testing.T) {
	t.Setenv("AUTH_IDENTITY_PROOF", identityProofEnv)

	spec, err := exposeSpec(t, "--auth", "siwe", "--auth-identity-headers", "3000")
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.HTTP.Auth.IdentityProof; got != identityProofEnv {
		t.Fatalf("identity proof = %q, want the AUTH_IDENTITY_PROOF value", got)
	}
}

// A flag typed on the command line is deliberate: without --auth-identity-headers
// it must be refused instead of starting a tunnel that sends no proof.
func TestExposeRefusesExplicitIdentityProofWithoutIdentityHeaders(t *testing.T) {
	for _, args := range [][]string{
		{"--auth", "siwe", "--auth-identity-proof", identityProofEnv, "3000"},
		{"--auth-identity-proof", identityProofEnv, "3000"},
	} {
		if _, err := exposeSpec(t, args...); err == nil {
			t.Errorf("portal expose %v started without --auth-identity-headers", args)
		}
	}
}
