package acme

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-jose/go-jose/v4"
)

// accountTestCA accepts real lego account requests and verifies the EAB against
// the account's public key. It does not replace the ACME transport or DNS provider.
func accountTestCA(t *testing.T, required bool) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "dGVzdC1hY21lLW5vbmNl")
		switch r.URL.Path {
		case "/directory", "/other-directory":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order",
				"revokeCert": base + "/revoke", "keyChange": base + "/key",
				"meta": map[string]any{"externalAccountRequired": required},
			})
		case "/nonce":
			w.WriteHeader(http.StatusNoContent)
		case "/account":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			outer, err := jose.ParseSignedJSON(string(data), []jose.SignatureAlgorithm{jose.ES256})
			if err != nil || len(outer.Signatures) != 1 || outer.Signatures[0].Protected.JSONWebKey == nil {
				t.Errorf("invalid ACME account JWS: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			key := outer.Signatures[0].Protected.JSONWebKey
			payload, err := outer.Verify(key.Key)
			var account acme.Account
			if err != nil || json.Unmarshal(payload, &account) != nil || !account.TermsOfServiceAgreed {
				t.Errorf("invalid signed account: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if required || len(account.ExternalAccountBinding) != 0 {
				binding, err := jose.ParseSignedJSON(string(account.ExternalAccountBinding), []jose.SignatureAlgorithm{jose.HS256})
				valid := false
				if err == nil && len(binding.Signatures) == 1 {
					boundKey, verifyErr := binding.Verify([]byte("test-only-eab-secret-for-account-binding!"))
					var bound jose.JSONWebKey
					if verifyErr == nil && json.Unmarshal(boundKey, &bound) == nil {
						got, _ := bound.Thumbprint(crypto.SHA256)
						want, _ := key.Thumbprint(crypto.SHA256)
						header := binding.Signatures[0].Protected
						valid = bytes.Equal(got, want) && header.KeyID == "test-kid" && header.ExtraHeaders[jose.HeaderKey("url")] == base+"/account"
					}
				}
				if !valid {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(acme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "invalid external account binding"})
					return
				}
			}
			w.Header().Set("Location", base+"/accounts/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(acme.Account{Status: acme.StatusValid, Orders: base + "/orders"})
		default:
			t.Errorf("unexpected ACME request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	trusted := filepath.Join(t.TempDir(), "directory.pem")
	if err := os.WriteFile(trusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", trusted)
	return server
}

func TestACMEAccountRegistration(t *testing.T) {
	hmac := base64.RawURLEncoding.EncodeToString([]byte("test-only-eab-secret-for-account-binding!"))
	for _, tc := range []struct {
		name, kid, hmac, wantError string
		required                   bool
	}{
		{name: "non-EAB CA without settings"},
		{name: "required EAB", required: true, kid: "test-kid", hmac: hmac},
		{name: "padded HMAC", required: true, kid: "test-kid", hmac: base64.URLEncoding.EncodeToString([]byte("test-only-eab-secret-for-account-binding!"))},
		{name: "optional EAB", kid: "test-kid", hmac: hmac},
		{name: "trimmed credentials", required: true, kid: " test-kid ", hmac: " " + hmac + " "},
		{name: "required credentials absent", required: true, wantError: "ACME_EAB_KID and ACME_EAB_HMAC"},
		{name: "KID alone", kid: "test-kid", wantError: "ACME_EAB_KID and ACME_EAB_HMAC"},
		{name: "HMAC alone", hmac: hmac, wantError: "ACME_EAB_KID and ACME_EAB_HMAC"},
		{name: "malformed HMAC", required: true, kid: "test-kid", hmac: "not!base64url", wantError: "could not decode hmac key"},
		{name: "rejected HMAC", required: true, kid: "test-kid", hmac: base64.RawURLEncoding.EncodeToString([]byte("wrong-eab-secret-for-account-binding!")), wantError: "invalid external account binding"},
		{name: "optional EAB rejected", kid: "test-kid", hmac: base64.RawURLEncoding.EncodeToString([]byte("wrong-eab-secret-for-account-binding!")), wantError: "invalid external account binding"},
		{name: "rejected KID", required: true, kid: "wrong-kid", hmac: hmac, wantError: "invalid external account binding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := accountTestCA(t, tc.required)
			cfg := Config{BaseDomain: "portal.example.com", KeyDir: t.TempDir(), DNSProvider: TypeCloudflare, CloudflareToken: "test-token", CADirURL: ca.URL + "/directory", EABKID: tc.kid, EABHMAC: tc.hmac}
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.newClient(t.Context())
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("registration error = %v, want %q", err, tc.wantError)
				}
				if tc.hmac != "" && strings.Contains(err.Error(), strings.TrimSpace(tc.hmac)) {
					t.Fatal("registration error exposed the HMAC secret")
				}
				if _, statErr := os.Stat(registrationFilePath(cfg.KeyDir, cfg.CADirURL)); !os.IsNotExist(statErr) {
					t.Fatalf("failed registration persisted account state: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A restart and the tenant CSR consumer must reuse the selected CA's
			// persisted account after its one-time EAB credentials are removed.
			cfg.EABKID, cfg.EABHMAC = "", ""
			restarted, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.newClient(t.Context()); err != nil {
				t.Fatalf("reuse registered account without EAB: %v", err)
			}
			user, path, err := restarted.newClientLoadUser("acme@portal.example.com", false)
			if err != nil || user.Registration == nil || user.Registration.URI != ca.URL+"/accounts/1" {
				t.Fatalf("tenant account did not load the selected CA registration: %v", err)
			}
			if _, err := restarted.newClientWithLoadedUser(t.Context(), user, path); err != nil {
				t.Fatalf("tenant account without EAB: %v", err)
			}
			if tc.required {
				cfg.CADirURL = ca.URL + "/other-directory"
				other, err := NewManager(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := other.newClient(t.Context()); err == nil || !strings.Contains(err.Error(), "ACME_EAB_KID and ACME_EAB_HMAC") {
					t.Fatalf("another directory reused the previous CA account: %v", err)
				}
				if _, err := restarted.newClient(t.Context()); err != nil {
					t.Fatalf("switching directories lost the original account: %v", err)
				}
			}
		})
	}
}

func TestCertificateCoversDomains(t *testing.T) {
	t.Parallel()

	domains := []string{"relay.example", "*.relay.example"}
	for _, tc := range []struct {
		name string
		sans []string
		want bool
	}{
		{"apex and wildcard", []string{"relay.example", "*.relay.example"}, true},
		{"wildcard without apex", []string{"*.relay.example"}, false},
		{"apex without wildcard", []string{"relay.example"}, false},
		{"single probe name without wildcard", []string{"relay.example", "probe.relay.example"}, false},
		{"different domain", []string{"other.example", "*.other.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{DNSNames: tc.sans}
			if got := certificateCoversDomains(cert, domains); got != tc.want {
				t.Fatalf("certificateCoversDomains(%v, %v) = %v, want %v", tc.sans, domains, got, tc.want)
			}
		})
	}
}

func TestCertificateUsable(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	domains := []string{"relay.example", "*.relay.example"}
	for _, tc := range []struct {
		name      string
		sans      []string
		notBefore time.Time
		notAfter  time.Time
		want      bool
	}{
		{"valid and covering", domains, now.Add(-day), now.Add(day), true},
		{"expired a second ago", domains, now.Add(-90 * day), now.Add(-time.Second), false},
		{"expires this instant", domains, now.Add(-90 * day), now, false},
		{"not valid yet on this clock", domains, now.Add(time.Minute), now.Add(90 * day), true},
		{"valid but another domain", []string{"other.example", "*.other.example"}, now.Add(-day), now.Add(day), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{DNSNames: tc.sans, NotBefore: tc.notBefore, NotAfter: tc.notAfter}
			if got := certificateUsable(cert, domains, now); got != tc.want {
				t.Fatalf("certificateUsable() = %v, want %v", got, tc.want)
			}
		})
	}
	if certificateUsable(nil, domains, now) {
		t.Fatal("certificateUsable(nil) = true, want false")
	}
}

func TestLocalDevelopmentCertificateReusable(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	domains := []string{"portal.localhost", "*.portal.localhost"}
	for _, tc := range []struct {
		name      string
		sans      []string
		notBefore time.Time
		notAfter  time.Time
		want      bool
	}{
		{"issued now for the longest validity Apple accepts", domains, now.Add(-time.Hour), now.Add(-time.Hour).Add(localDevelopmentCertificateValidity), true},
		{"one second longer than Apple accepts", domains, now.Add(-time.Hour), now.Add(-time.Hour).Add(localDevelopmentCertificateValidity + time.Second), false},
		{"ten years, as older relays issued", domains, now.Add(-day), now.Add(3650 * day), false},
		{"expires just after the renewal threshold", domains, now.Add(-769 * day), now.Add(defaultRenewThreshold + day), true},
		{"expires within the renewal threshold", domains, now.Add(-771 * day), now.Add(defaultRenewThreshold - day), false},
		{"another domain", []string{"relay.example", "*.relay.example"}, now.Add(-time.Hour), now.Add(800 * day), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{DNSNames: tc.sans, NotBefore: tc.notBefore, NotAfter: tc.notAfter}
			if got := localDevelopmentCertificateReusable(cert, domains, now); got != tc.want {
				t.Fatalf("localDevelopmentCertificateReusable() = %v, want %v", got, tc.want)
			}
		})
	}
	if localDevelopmentCertificateReusable(nil, domains, now) {
		t.Fatal("localDevelopmentCertificateReusable(nil) = true, want false")
	}
}

func TestReusableCertificateIsPerCAAndUnexpired(t *testing.T) {
	t.Parallel()

	const (
		baseDomain = "portal.example.com"
		day        = 24 * time.Hour
	)
	keyDir := t.TempDir()
	now := time.Now()
	productionCert, productionKey := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	if err := writeRelayCertificate(t, productionCert, productionKey, baseDomain, now.Add(-time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate(production) error = %v", err)
	}
	stagingCert, stagingKey := certificateFilePaths(keyDir, lego.LEDirectoryStaging)
	if err := writeRelayCertificate(t, stagingCert, stagingKey, baseDomain, now.Add(30*day)); err != nil {
		t.Fatalf("writeRelayCertificate(staging) error = %v", err)
	}
	managerFor := func(caDirURL string) *Manager {
		t.Helper()
		manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53, CADirURL: caDirURL})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		return manager
	}

	if _, _, ok := managerFor(lego.LEDirectoryProduction).reusableCertificate(now); ok {
		t.Fatal("reusableCertificate() = true for the expired production certificate, want false")
	}
	certFile, keyFile, ok := managerFor(lego.LEDirectoryStaging).reusableCertificate(now)
	if !ok || certFile != stagingCert || keyFile != stagingKey {
		t.Fatalf("reusableCertificate() = %q, %q, %v; want the valid staging certificate", certFile, keyFile, ok)
	}
	other := managerFor("https://acme.example.test/directory")
	if _, _, ok := other.reusableCertificate(now); ok {
		t.Fatal("reusableCertificate() = true for a CA with no stored certificate, want false")
	}
}

func TestEvaluateRenewal(t *testing.T) {
	t.Parallel()

	const (
		day      = 24 * time.Hour
		lifetime = 90 * day
	)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	domains := []string{"relay.example", "*.relay.example"}
	pastWindow := &acme.Window{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour)}
	farWindow := &acme.Window{Start: now.Add(72 * time.Hour), End: now.Add(73 * time.Hour)}
	soonWindow := &acme.Window{Start: now.Add(2 * time.Hour), End: now.Add(3 * time.Hour)}

	for _, tc := range []struct {
		name        string
		cert        *x509.Certificate
		domains     []string
		ari         *certificate.RenewalInfoResponse
		wantRenew   bool
		wantReplace bool
		wantRecheck time.Duration
	}{
		{"due window renews early and replaces the certificate", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(pastWindow, 0), true, true, 24 * time.Hour},
		{"future window defers", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(farWindow, 0), false, false, 24 * time.Hour},
		{"future window defers even below the fallback threshold", newEvaluateRenewalCert(now, domains, 20*day, lifetime), domains, newEvaluateRenewalARI(farWindow, 0), false, false, 24 * time.Hour},
		{"retry after below one hour is raised to one hour", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(soonWindow, 5*time.Minute), false, false, time.Hour},
		{"retry after above one day is capped at one day", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(farWindow, 72*time.Hour), false, false, 24 * time.Hour},
		{"window before the next check renews now", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(soonWindow, 6*time.Hour), true, true, 6 * time.Hour},
		{"expiry floor overrides a deferring window", newEvaluateRenewalCert(now, domains, 3*day, lifetime), domains, newEvaluateRenewalARI(farWindow, 0), true, true, 24 * time.Hour},
		{"next check is no later than the expiry floor", newEvaluateRenewalCert(now, domains, 7*day+2*time.Hour, lifetime), domains, newEvaluateRenewalARI(farWindow, 0), false, false, 2 * time.Hour},
		{"floor is a tenth of a short lifetime", newEvaluateRenewalCert(now, domains, 3*day, 6*day), domains, newEvaluateRenewalARI(farWindow, 0), false, false, 24 * time.Hour},
		{"short lifetime below its floor renews", newEvaluateRenewalCert(now, domains, 10*time.Hour, 6*day), domains, newEvaluateRenewalARI(farWindow, 0), true, true, 24 * time.Hour},
		{"expired certificate renews without ReplacesCertID", newEvaluateRenewalCert(now, domains, -time.Hour, lifetime), domains, newEvaluateRenewalARI(farWindow, 0), true, false, 24 * time.Hour},
		{"domain mismatch renews without ReplacesCertID", newEvaluateRenewalCert(now, domains, 60*day, lifetime), []string{"other.example", "*.other.example"}, newEvaluateRenewalARI(farWindow, 0), true, false, 24 * time.Hour},
		{"zero window falls back to the threshold", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(&acme.Window{}, 0), false, false, 24 * time.Hour},
		{"zero window renews below the threshold", newEvaluateRenewalCert(now, domains, 10*day, lifetime), domains, newEvaluateRenewalARI(&acme.Window{}, 0), true, false, 24 * time.Hour},
		{"inverted window falls back to the threshold", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, newEvaluateRenewalARI(&acme.Window{Start: farWindow.End, End: farWindow.Start}, 0), false, false, 24 * time.Hour},
		{"inverted window renews below the threshold", newEvaluateRenewalCert(now, domains, 10*day, lifetime), domains, newEvaluateRenewalARI(&acme.Window{Start: pastWindow.End, End: pastWindow.Start}, 0), true, false, 24 * time.Hour},
		{"missing ARI falls back to the threshold", newEvaluateRenewalCert(now, domains, 60*day, lifetime), domains, nil, false, false, 24 * time.Hour},
		{"missing ARI renews below the threshold", newEvaluateRenewalCert(now, domains, 10*day, lifetime), domains, nil, true, false, 24 * time.Hour},
		{"certificate that is not valid yet is left alone", newEvaluateRenewalCert(now, domains, 60*day, 59*day), domains, nil, false, false, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			renew, replacesCertID, recheck := evaluateRenewal(tc.cert, tc.domains, tc.ari, now)
			if renew != tc.wantRenew || (replacesCertID != "") != tc.wantReplace || recheck != tc.wantRecheck {
				t.Fatalf("evaluateRenewal = (%v, %q, %v); want (%v, replaces=%v, %v)", renew, replacesCertID, recheck, tc.wantRenew, tc.wantReplace, tc.wantRecheck)
			}
		})
	}
}

func newEvaluateRenewalCert(now time.Time, domains []string, remaining, validity time.Duration) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		AuthorityKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		DNSNames:       domains,
		NotBefore:      now.Add(remaining - validity),
		NotAfter:       now.Add(remaining),
	}
}

func newEvaluateRenewalARI(window *acme.Window, retryAfter time.Duration) *certificate.RenewalInfoResponse {
	return &certificate.RenewalInfoResponse{
		RenewalInfoResponse: acme.RenewalInfoResponse{SuggestedWindow: *window},
		RetryAfter:          retryAfter,
	}
}

func TestNormalizeCADirURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		valid bool
	}{
		{name: "empty defaults to Let's Encrypt production", input: "", valid: true},
		{name: "custom https CA directory", input: "https://ca.example/directory", valid: true},
		{name: "local test CA over https", input: "https://localhost:14000/dir", valid: true},
		{name: "loopback http rejected, lego only speaks https", input: "http://127.0.0.1:14000/dir", valid: false},
		{name: "http rejected", input: "http://acme.example.com/directory", valid: false},
		{name: "scheme-less address rejected", input: "acme.example.com/directory", valid: false},
		{name: "https without a host rejected", input: "https://:14000/dir", valid: false},
		{name: "query string rejected", input: "https://acme.example.com/directory?foo=1", valid: false},
		{name: "userinfo rejected", input: "https://user:pass@acme.example.com/directory", valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCADirURL(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("NormalizeCADirURL(%q) = (%q, %v), want valid=%v", tc.input, got, err, tc.valid)
			}
		})
	}
}

func TestNormalizeCADirURLIsCanonical(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ input, want string }{
		{"  https://CA.Example/Directory  ", "https://ca.example/Directory"},
		{"HTTPS://ca.example:8443/dir", "https://ca.example:8443/dir"},
		{"https://ca.example/dir/", "https://ca.example/dir/"},
		{"HTTPS://ACME-V02.API.LETSENCRYPT.ORG/directory", lego.LEDirectoryProduction},
		{lego.LEDirectoryStaging, lego.LEDirectoryStaging},
		{"", lego.LEDirectoryProduction},
	} {
		if got, err := NormalizeCADirURL(tc.input); err != nil || got != tc.want {
			t.Errorf("NormalizeCADirURL(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	upper, _ := NormalizeCADirURL("https://CA.Example/dir")
	lower, _ := NormalizeCADirURL("https://ca.example/dir")
	if registrationFilePath("/state", upper) != registrationFilePath("/state", lower) {
		t.Error("two spellings of one directory got different registration files")
	}
}

func TestRegistrationFilePathIsScopedToCADirectory(t *testing.T) {
	t.Parallel()

	const keyDir = "/state"
	legacy := filepath.Join(keyDir, registrationFileName)

	production := registrationFilePath(keyDir, lego.LEDirectoryProduction)
	if production != legacy {
		t.Fatalf("production registration = %q; want the legacy %q so existing installations keep it", production, legacy)
	}
	staging := registrationFilePath(keyDir, lego.LEDirectoryStaging)
	other := registrationFilePath(keyDir, "https://ca.example/directory")
	if staging == production || other == production || staging == other {
		t.Fatalf("registrations must differ per directory: production %q, staging %q, other %q", production, staging, other)
	}
	for _, path := range []string{staging, other} {
		if filepath.Dir(path) != keyDir {
			t.Fatalf("registration %q left the key directory %q", path, keyDir)
		}
	}
	if got := registrationFilePath(keyDir, lego.LEDirectoryStaging); got != staging {
		t.Fatalf("staging registration = %q; want the stable %q", got, staging)
	}
	if got := registrationFilePath(keyDir, lego.LEDirectoryProduction); got != production {
		t.Fatalf("production registration after switching back = %q; want %q", got, production)
	}
}

func TestCertificateFilePathsAreScopedToCADirectory(t *testing.T) {
	t.Parallel()

	const keyDir = "/state"
	productionCert, productionKey := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	if productionCert != filepath.Join(keyDir, fullChainFileName) || productionKey != filepath.Join(keyDir, keyFileName) {
		t.Fatalf("production certificate files = %q, %q; want the legacy names so existing installations and manual files keep working", productionCert, productionKey)
	}
	stagingCert, stagingKey := certificateFilePaths(keyDir, lego.LEDirectoryStaging)
	otherCert, otherKey := certificateFilePaths(keyDir, "https://ca.example/directory")

	seen := make(map[string]bool)
	for _, path := range []string{productionCert, productionKey, stagingCert, stagingKey, otherCert, otherKey} {
		if seen[path] {
			t.Fatalf("certificate files collide at %q", path)
		}
		seen[path] = true
		if filepath.Dir(path) != keyDir {
			t.Fatalf("certificate file %q left the key directory %q", path, keyDir)
		}
	}
	if cert, key := certificateFilePaths(keyDir, lego.LEDirectoryStaging); cert != stagingCert || key != stagingKey {
		t.Fatalf("staging certificate files = %q, %q; want the stable %q, %q", cert, key, stagingCert, stagingKey)
	}
}

func TestTLSFilesSelectOnlyTheConfiguredCAsCertificate(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, baseDomain); err != nil {
		t.Fatalf("writeManualRelayCertificate() error = %v", err)
	}
	production := newScopedCAManager(t, keyDir, baseDomain, "")
	staging := newScopedCAManager(t, keyDir, baseDomain, lego.LEDirectoryStaging)
	productionCert, _ := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	checkInitialCAFiles(t, production, staging, productionCert)
	checkCAFilesAfterStagingIssue(t, staging, production, keyDir, baseDomain)
}

func newScopedCAManager(t *testing.T, keyDir, baseDomain, caDirURL string) *Manager {
	t.Helper()
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53, CADirURL: caDirURL})
	if err != nil {
		t.Fatalf("NewManager(%q) error = %v", caDirURL, err)
	}
	return manager
}

func checkInitialCAFiles(t *testing.T, production, staging *Manager, productionCert string) {
	t.Helper()
	if cert, _, err := production.TLSFiles(); err != nil || cert != productionCert {
		t.Fatalf("production TLSFiles() = %q, %v; want %q", cert, err, productionCert)
	}
	if cert, _, err := staging.TLSFiles(); err == nil {
		t.Fatalf("staging TLSFiles() = %q; want no certificate, since only Let's Encrypt production issued one", cert)
	}
}

func checkCAFilesAfterStagingIssue(t *testing.T, staging, production *Manager, keyDir, baseDomain string) {
	t.Helper()
	stagingCert, stagingKey := certificateFilePaths(keyDir, lego.LEDirectoryStaging)
	if err := writeRelayCertificate(t, stagingCert, stagingKey, baseDomain, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	if cert, key, err := staging.TLSFiles(); err != nil || cert != stagingCert || key != stagingKey {
		t.Fatalf("staging TLSFiles() = %q, %q, %v; want %q, %q", cert, key, err, stagingCert, stagingKey)
	}
	productionCert, _ := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	if cert, _, err := production.TLSFiles(); err != nil || cert != productionCert {
		t.Fatalf("production TLSFiles() after staging issued = %q, %v; want %q", cert, err, productionCert)
	}
}

func TestShouldRenewReadsTheConfiguredCAsCertificate(t *testing.T) {
	t.Parallel()

	const baseDomain = "portal.example.com"
	keyDir := t.TempDir()
	if err := writeManualRelayCertificate(t, keyDir, baseDomain); err != nil {
		t.Fatalf("writeManualRelayCertificate() error = %v", err)
	}
	stagingCert, stagingKey := certificateFilePaths(keyDir, lego.LEDirectoryStaging)
	if err := writeRelayCertificate(t, stagingCert, stagingKey, baseDomain, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53, CADirURL: lego.LEDirectoryStaging})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if renew, _, _ := manager.shouldRenew(t.Context()); !renew {
		t.Fatal("shouldRenew() = false; want the expired staging certificate renewed")
	}
}

func TestLocalDevelopmentCertificateIgnoresTheConfiguredCA(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()
	manager, err := NewManager(Config{BaseDomain: "localhost", KeyDir: keyDir, CADirURL: lego.LEDirectoryStaging})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	certFile, keyFile, err := manager.EnsureCertificate(t.Context())
	if err != nil {
		t.Fatalf("EnsureCertificate() error = %v", err)
	}
	wantCert, wantKey := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	if certFile != wantCert || keyFile != wantKey {
		t.Fatalf("EnsureCertificate() = %q, %q; want the legacy %q, %q", certFile, keyFile, wantCert, wantKey)
	}
}
