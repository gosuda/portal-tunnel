package main

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
)

func exposeSpec(t *testing.T, args ...string) (tunnel.Spec, error) {
	t.Helper()
	var cfg tunnel.Config
	var flags exposeFlags
	fs := cli.NewFlagSet("expose", printExposeUsage)
	registerExposeFlags(fs, &cfg, &flags)
	if err := cli.ParseFlagSet(fs, args, printExposeUsage); err != nil {
		t.Fatalf("parse portal expose %v: %v", args, err)
	}
	cfg.TargetAddr = fs.Arg(0)
	return tunnelSpecFromExposeFlags(fs, cfg, flags)
}

func setOIDCEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("AUTH_OIDC_CLIENT_ID", "client-id")
	t.Setenv("AUTH_OIDC_CLIENT_SECRET", "client-secret")
}

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

func TestExposeAuthSAMLEnv(t *testing.T) {
	t.Setenv("AUTH_SAML_METADATA_URL", "https://idp.example/metadata")
	t.Setenv("AUTH_SAML_ENTITY_ID", "urn:portal:app")
	t.Setenv("AUTH_SAML_SUBJECT_ATTRIBUTE", "email")

	for _, args := range [][]string{{"3000"}, {"--auth", "siwe", "3000"}} {
		spec, err := exposeSpec(t, args...)
		if err != nil {
			t.Errorf("portal expose %v: %v", args, err)
			continue
		}
		if spec.HTTP == nil || spec.HTTP.Auth == nil {
			continue
		}
		if auth := spec.HTTP.Auth; auth.SAMLMetadataURL != "" || auth.SAMLEntityID != "" {
			t.Errorf("portal expose %v carried AUTH_SAML_* into %+v", args, auth)
		}
	}
	spec, err := exposeSpec(t, "--auth", "saml", "--auth-email-list", "@example.com", "3000")
	if err != nil {
		t.Fatal(err)
	}
	if auth := spec.HTTP.Auth; auth.SAMLMetadataURL != "https://idp.example/metadata" || auth.SAMLEntityID != "urn:portal:app" || auth.SAMLSubjectAttribute != "email" {
		t.Fatalf("--auth saml config = %+v, want the AUTH_SAML_* values", auth)
	}
	if _, err := exposeSpec(t, "--auth", "siwe", "--auth-saml-entity-id", "urn:portal:app", "3000"); err == nil {
		t.Error("portal expose started with --auth-saml-entity-id but without --auth saml")
	}
}

func TestExposeAuthEmailEnv(t *testing.T) {
	t.Setenv("AUTH_SMTP_ADDR", "smtp.example:587")
	t.Setenv("AUTH_SMTP_USERNAME", "portal")
	t.Setenv("AUTH_SMTP_PASSWORD", "smtp-secret")
	t.Setenv("AUTH_SMTP_FROM", "login@example.com")

	for _, args := range [][]string{{"3000"}, {"--auth", "siwe", "3000"}} {
		spec, err := exposeSpec(t, args...)
		if err != nil {
			t.Errorf("portal expose %v: %v", args, err)
			continue
		}
		if spec.HTTP != nil && spec.HTTP.Auth != nil && spec.HTTP.Auth.EmailConfig != (appauth.EmailConfig{}) {
			t.Errorf("portal expose %v carried AUTH_SMTP_* into the auth settings", args)
		}
	}
	spec, err := exposeSpec(t, "--auth", "email", "--auth-email-list", "alice@example.com", "3000")
	if err != nil {
		t.Fatal(err)
	}
	want := appauth.EmailConfig{SMTPAddr: "smtp.example:587", SMTPUsername: "portal", SMTPPassword: "smtp-secret", SMTPFrom: "login@example.com"}
	if spec.HTTP.Auth.EmailConfig != want {
		t.Fatal("--auth email did not take the AUTH_SMTP_* values")
	}
	if _, err := exposeSpec(t, "--auth", "siwe", "--auth-smtp-from", "login@example.com", "3000"); err == nil {
		t.Error("portal expose started with --auth-smtp-from but without --auth email")
	}
	if _, err := exposeSpec(t, "--auth", "email", "3000"); err == nil {
		t.Error("portal expose --auth email started without an allowlist")
	}
	if _, err := exposeSpec(t, "--auth", "email", "--auth-email-list", "alice@example.com", "--auth-smtp-addr", " ", "3000"); err == nil {
		t.Error("portal expose --auth email started without an SMTP server")
	}
}

const identityProofEnv = "test-proof-0123456789"

func TestExposeIgnoresIdentityProofEnvWithoutIdentityHeaders(t *testing.T) {
	t.Setenv("AUTH_IDENTITY_PROOF", identityProofEnv)

	for _, args := range [][]string{{"3000"}, {"--tcp", "3000"}, {"--auth", "siwe", "3000"}} {
		spec, err := exposeSpec(t, args...)
		if err != nil {
			t.Errorf("portal expose %v: %v", args, err)
			continue
		}
		if spec.HTTP != nil && spec.HTTP.Auth != nil && spec.HTTP.Auth.IdentityProof != "" {
			t.Errorf("portal expose %v carried AUTH_IDENTITY_PROOF into %+v", args, spec.HTTP.Auth)
		}
	}
	if spec, _ := exposeSpec(t, "3000"); spec.HTTP != nil {
		t.Errorf("AUTH_IDENTITY_PROOF alone enabled HTTP handling: %+v", spec.HTTP)
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

func TestExposeLocalTLSCertificates(t *testing.T) {
	spec, err := exposeSpec(t, "--tls-cert", "cert.pem", "--tls-key", "key.pem", "3000")
	if err != nil {
		t.Fatal(err)
	}
	if spec.TLSCert != "cert.pem" || spec.TLSKey != "key.pem" {
		t.Fatalf("certificate paths = %q, %q", spec.TLSCert, spec.TLSKey)
	}
	if _, err := exposeSpec(t, "--tls-cert", "cert.pem", "3000"); err == nil {
		t.Fatal("unpaired certificate flag accepted")
	}
}

func TestExposeAutomaticTLS(t *testing.T) {
	spec, err := exposeSpec(t, "--tls-auto", "--tls-require-local", "3000")
	if err != nil {
		t.Fatal(err)
	}
	if !spec.TLSAuto || !spec.TLSRequireLocal || spec.TLSStateDir != "identity.json.tls" {
		t.Fatalf("automatic TLS options = %+v", spec)
	}
	if _, err := exposeSpec(t, "--tls-state-dir", "certs", "3000"); err == nil {
		t.Fatal("state directory silently enabled automatic TLS")
	}
	if _, err := exposeSpec(t, "--tls-auto", "--identity-json", "{}", "3000"); err == nil {
		t.Fatal("in-memory identity silently chose a persistence directory")
	}
}

func TestExposeCertificateMonitoring(t *testing.T) {
	spec, err := exposeSpec(t, "--tls-monitor-state-dir", "evidence", "--tls-monitor-baseline", "baseline.json", "--tls-monitor-dns-resolver", "9.9.9.9:53", "3000")
	if err != nil {
		t.Fatal(err)
	}
	monitor := spec.CertificateMonitor
	if monitor == nil || monitor.StateDir != "evidence" || monitor.BaselineFile != "baseline.json" || monitor.DNSResolver != "9.9.9.9:53" {
		t.Fatalf("certificate monitoring options = %+v", monitor)
	}
	for _, args := range [][]string{
		{"--tls-monitor-baseline", "baseline.json", "3000"},
		{"--tls-monitor-dns-resolver", "9.9.9.9:53", "3000"},
	} {
		if _, err := exposeSpec(t, args...); err == nil {
			t.Fatalf("portal expose %v silently enabled monitoring without a state directory", args)
		}
	}
}
