package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/gateway"
)

// startOIDCRuntime starts a tunnel protected by OIDC at issuer. Its only relay
// is unreachable, which is enough to assemble the gateway and run the
// provider check.
func startOIDCRuntime(t *testing.T, issuer string) *Runtime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runtime, err := Start(ctx, Spec{
		Identity:  IdentitySpec{Name: "auth-check", Path: filepath.Join(t.TempDir(), "identity.json")},
		Relays:    RelaySpec{URLs: []string{"https://127.0.0.1:1"}},
		Transport: TransportSpec{Target: "127.0.0.1:3000"},
		HTTP: &HTTPConfig{Auth: &gateway.ApplicationAuthConfig{
			Provider:       gateway.ApplicationAuthProviderOIDC,
			AllowedWallets: []string{"alice@example.com"},
			OIDCIssuerURL:  issuer,
			OIDCClientID:   "client-123",
		}},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = runtime.Close()
	})
	return runtime
}

// newOIDCIssuer serves a minimal OIDC provider once release is closed, and
// closes the returned channel when the first request arrives. An unhealthy
// provider answers every request with a server error.
func newOIDCIssuer(t *testing.T, release <-chan struct{}, healthy bool) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "ES256", Use: "sig"}}}
	requested := make(chan struct{})
	var once sync.Once
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(requested) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		switch {
		case !healthy:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case r.URL.Path == "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 issuer.URL,
				"authorization_endpoint": issuer.URL + "/authorize",
				"token_endpoint":         issuer.URL + "/token",
				"jwks_uri":               issuer.URL + "/jwks",
			})
		case r.URL.Path == "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	return issuer, requested
}

func waitForAuthProviderCheck(t *testing.T, runtime *Runtime) error {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Second)
	for {
		if checked, err := runtime.AuthProviderCheck(); checked {
			return err
		}
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatal("auth provider check did not finish")
			return nil
		}
	}
}

func TestRuntimeAuthProviderCheck(t *testing.T) {
	t.Run("usable provider", func(t *testing.T) {
		release := make(chan struct{})
		issuer, requested := newOIDCIssuer(t, release, true)
		runtime := startOIDCRuntime(t, issuer.URL)
		select {
		case <-requested:
		case <-time.After(10 * time.Second):
			t.Fatal("provider was never asked")
		}
		if checked, _ := runtime.AuthProviderCheck(); checked {
			t.Fatal("checked before the provider answered")
		}
		close(release)
		if err := waitForAuthProviderCheck(t, runtime); err != nil {
			t.Fatalf("usable provider reported %v", err)
		}
	})

	t.Run("unusable provider", func(t *testing.T) {
		release := make(chan struct{})
		close(release)
		issuer, _ := newOIDCIssuer(t, release, false)
		runtime := startOIDCRuntime(t, issuer.URL)
		if err := waitForAuthProviderCheck(t, runtime); err == nil {
			t.Fatal("unusable provider reported no error")
		}
	})
}
