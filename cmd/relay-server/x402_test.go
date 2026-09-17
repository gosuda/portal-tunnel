package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestResolveX402FacilitatorRequiresRecipient(t *testing.T) {
	cfg := appConfig{X402Enabled: true}
	if _, err := resolveX402Facilitator(cfg); err == nil {
		t.Fatal("resolveX402Facilitator() error = nil, want error for enabled x402 without recipient")
	}
	cfg.X402PayTo = "0xrecipient"
	settings, err := resolveX402Facilitator(cfg)
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil with recipient set", err)
	}
	if !settings.Enabled || settings.Testnet {
		t.Fatalf("resolveX402Facilitator() = %+v, want enabled mainnet with recipient set", settings)
	}

	testnetSettings, err := resolveX402Facilitator(appConfig{X402Enabled: true, X402Testnet: true, X402PayTo: "0xrecipient"})
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil with recipient set", err)
	}
	if !testnetSettings.Enabled || !testnetSettings.Testnet {
		t.Fatalf("resolveX402Facilitator() = %+v, want enabled testnet with recipient set", testnetSettings)
	}

	disabled, err := resolveX402Facilitator(appConfig{X402PayTo: "0xrecipient"})
	if err != nil {
		t.Fatalf("resolveX402Facilitator() error = %v, want nil when disabled", err)
	}
	if disabled.Enabled {
		t.Fatalf("resolveX402Facilitator() = %+v, want disabled without --x402-enabled", disabled)
	}
}

func TestComposeRelayHandlerPreservesDomainX402Metadata(t *testing.T) {
	base := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The generic relay reports a disabled facilitator; the process owner
		// fills in its enabled application configuration.
		_, _ = w.Write([]byte(`{"ok":true,"data":{"protocol_version":"2","release_version":"test","ens":{},"x402":{"enabled":false}}}`))
	})
	settings := x402FacilitatorSettings{Enabled: true, Testnet: true, PayTo: "0xrecipient", PortalURL: "https://relay.example"}
	handler, err := composeRelayHandler(settings, base)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.PathSDKDomain, nil))
	var response types.APIEnvelope[types.DomainResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	info := response.Data.X402
	if rec.Code != http.StatusOK || !info.Enabled || info.PayTo != settings.PayTo || info.URL != settings.PortalURL+types.PathX402Facilitator || info.SupportedURL != settings.PortalURL+types.X402SupportedPath {
		t.Fatalf("domain metadata = %+v, status = %d", info, rec.Code)
	}
}

// Enabling the facilitator must interpose it on /api/x402 only: the payment
// endpoints answer without reaching the relay handler, and every other path
// still does. With payments disabled the relay handler must see /api/x402 too.
func TestComposeRelayHandlerMountsFacilitatorOnlyWhenEnabled(t *testing.T) {
	var relayHits []string
	relayAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayHits = append(relayHits, r.URL.Path)
		if r.URL.Path == types.X402SupportedPath {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	disabled, err := composeRelayHandler(x402FacilitatorSettings{}, relayAPI)
	if err != nil {
		t.Fatalf("composeRelayHandler() error = %v, want nil when disabled", err)
	}
	rec := httptest.NewRecorder()
	disabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.X402SupportedPath, nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("disabled facilitator status = %d, want relay handler to own %s (%d)", rec.Code, types.X402SupportedPath, http.StatusTeapot)
	}

	enabled, err := composeRelayHandler(x402FacilitatorSettings{Enabled: true}, relayAPI)
	if err != nil {
		t.Fatalf("composeRelayHandler() error = %v, want nil when enabled", err)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.X402SupportedPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d from the mounted facilitator", types.X402SupportedPath, rec.Code, http.StatusOK)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("GET /app status = %d, want %d from the relay handler", rec.Code, http.StatusNoContent)
	}
	if len(relayHits) != 2 || relayHits[0] != types.X402SupportedPath || relayHits[1] != "/app" {
		t.Fatalf("relay handler saw %v, want [%s /app] (the facilitator must answer %s)", relayHits, types.X402SupportedPath, types.X402SupportedPath)
	}
}
