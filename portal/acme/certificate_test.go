package acme

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

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
	newCert := func(remaining, validity time.Duration) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:   big.NewInt(12345),
			AuthorityKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			DNSNames:       domains,
			NotBefore:      now.Add(remaining - validity),
			NotAfter:       now.Add(remaining),
		}
	}
	pastWindow := &legoacme.Window{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour)}
	farWindow := &legoacme.Window{Start: now.Add(72 * time.Hour), End: now.Add(73 * time.Hour)}
	soonWindow := &legoacme.Window{Start: now.Add(2 * time.Hour), End: now.Add(3 * time.Hour)}
	ariFor := func(window *legoacme.Window, retryAfter time.Duration) *certificate.RenewalInfoResponse {
		return &certificate.RenewalInfoResponse{
			RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: *window},
			RetryAfter:          retryAfter,
		}
	}

	for _, tc := range []struct {
		name        string
		cert        *x509.Certificate
		domains     []string
		ari         *certificate.RenewalInfoResponse
		wantRenew   bool
		wantReplace bool
		wantRecheck time.Duration
	}{
		{"due window renews early and replaces the certificate", newCert(60*day, lifetime), domains, ariFor(pastWindow, 0), true, true, 24 * time.Hour},
		{"future window defers", newCert(60*day, lifetime), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"future window defers even below the fallback threshold", newCert(20*day, lifetime), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"retry after below one hour is raised to one hour", newCert(60*day, lifetime), domains, ariFor(soonWindow, 5*time.Minute), false, false, time.Hour},
		{"retry after above one day is capped at one day", newCert(60*day, lifetime), domains, ariFor(farWindow, 72*time.Hour), false, false, 24 * time.Hour},
		{"window before the next check renews now", newCert(60*day, lifetime), domains, ariFor(soonWindow, 6*time.Hour), true, true, 6 * time.Hour},
		{"expiry floor overrides a deferring window", newCert(3*day, lifetime), domains, ariFor(farWindow, 0), true, true, 24 * time.Hour},
		{"next check is no later than the expiry floor", newCert(7*day+2*time.Hour, lifetime), domains, ariFor(farWindow, 0), false, false, 2 * time.Hour},
		{"floor is a tenth of a short lifetime", newCert(3*day, 6*day), domains, ariFor(farWindow, 0), false, false, 24 * time.Hour},
		{"short lifetime below its floor renews", newCert(10*time.Hour, 6*day), domains, ariFor(farWindow, 0), true, true, 24 * time.Hour},
		{"expired certificate renews without ReplacesCertID", newCert(-time.Hour, lifetime), domains, ariFor(farWindow, 0), true, false, 24 * time.Hour},
		{"domain mismatch renews without ReplacesCertID", newCert(60*day, lifetime), []string{"other.example", "*.other.example"}, ariFor(farWindow, 0), true, false, 24 * time.Hour},
		{"zero window falls back to the threshold", newCert(60*day, lifetime), domains, ariFor(&legoacme.Window{}, 0), false, false, 24 * time.Hour},
		{"zero window renews below the threshold", newCert(10*day, lifetime), domains, ariFor(&legoacme.Window{}, 0), true, false, 24 * time.Hour},
		{"inverted window falls back to the threshold", newCert(60*day, lifetime), domains, ariFor(&legoacme.Window{Start: farWindow.End, End: farWindow.Start}, 0), false, false, 24 * time.Hour},
		{"inverted window renews below the threshold", newCert(10*day, lifetime), domains, ariFor(&legoacme.Window{Start: pastWindow.End, End: pastWindow.Start}, 0), true, false, 24 * time.Hour},
		{"missing ARI falls back to the threshold", newCert(60*day, lifetime), domains, nil, false, false, 24 * time.Hour},
		{"missing ARI renews below the threshold", newCert(10*day, lifetime), domains, nil, true, false, 24 * time.Hour},
		{"certificate that is not valid yet is left alone", newCert(60*day, 59*day), domains, nil, false, false, 24 * time.Hour},
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
	newManager := func(caDirURL string) *Manager {
		t.Helper()
		manager, err := NewManager(Config{BaseDomain: baseDomain, KeyDir: keyDir, DNSProvider: TypeRoute53, CADirURL: caDirURL})
		if err != nil {
			t.Fatalf("NewManager(%q) error = %v", caDirURL, err)
		}
		return manager
	}
	production, staging := newManager(""), newManager(lego.LEDirectoryStaging)

	productionCert, _ := certificateFilePaths(keyDir, lego.LEDirectoryProduction)
	if cert, _, err := production.TLSFiles(); err != nil || cert != productionCert {
		t.Fatalf("production TLSFiles() = %q, %v; want %q", cert, err, productionCert)
	}
	if cert, _, err := staging.TLSFiles(); err == nil {
		t.Fatalf("staging TLSFiles() = %q; want no certificate, since only Let's Encrypt production issued one", cert)
	}

	stagingCert, stagingKey := certificateFilePaths(keyDir, lego.LEDirectoryStaging)
	if err := writeRelayCertificate(t, stagingCert, stagingKey, baseDomain, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("writeRelayCertificate() error = %v", err)
	}
	if cert, key, err := staging.TLSFiles(); err != nil || cert != stagingCert || key != stagingKey {
		t.Fatalf("staging TLSFiles() = %q, %q, %v; want %q, %q", cert, key, err, stagingCert, stagingKey)
	}
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

func TestNewClientRefusesDirectoriesRequiringExternalAccountBinding(t *testing.T) {
	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/account",
			"newOrder":   base + "/order",
			"revokeCert": base + "/revoke",
			"keyChange":  base + "/key",
			"meta":       map[string]any{"externalAccountRequired": true},
		})
	}))
	t.Cleanup(directory.Close)
	trusted := filepath.Join(t.TempDir(), "directory.pem")
	if err := os.WriteFile(trusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: directory.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", trusted)

	manager, err := NewManager(Config{BaseDomain: "portal.example.com", KeyDir: t.TempDir(), DNSProvider: TypeRoute53, CADirURL: directory.URL})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, err := manager.newClient(t.Context()); err == nil || !strings.Contains(err.Error(), "external account binding") {
		t.Fatalf("newClient() error = %v; want one saying the directory requires external account binding", err)
	}
}
