package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestComposeRelayHandlerServesDomainWireShape pins the relay's /sdk/domain
// wire contract: the x402 object is always present — filled when the relay
// mounts the facilitator, exactly the disabled shape when it does not.
func TestComposeRelayHandlerServesDomainWireShape(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		settings    x402FacilitatorSettings
		wantEnabled bool
	}{
		{
			name:     "disabled keeps the x402 key with enabled false",
			settings: x402FacilitatorSettings{},
		},
		{
			name: "enabled publishes facilitator metadata",
			settings: x402FacilitatorSettings{
				Enabled:   true,
				Testnet:   true,
				PayTo:     "0x" + strings.Repeat("a", 64),
				PortalURL: "https://relay.example.com",
			},
			wantEnabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, err := portal.NewServer(portal.ServerConfig{PortalURL: "https://localhost", StateDir: t.TempDir()})
			if err != nil {
				t.Fatalf("new server: %v", err)
			}
			handler, err := composeRelayHandler(tc.settings, server, http.NotFoundHandler())
			if err != nil {
				t.Fatalf("compose relay handler: %v", err)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.PathSDKDomain, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", types.PathSDKDomain, rec.Code)
			}
			// Presence check against the raw body: an omitted x402 key must
			// fail here rather than decoding into a zero value.
			if !strings.Contains(rec.Body.String(), `"x402":`) {
				t.Fatalf("/sdk/domain response omits the x402 object: %s", rec.Body.String())
			}
			var payload struct {
				Data struct {
					X402 *struct {
						Enabled      bool   `json:"enabled"`
						URL          string `json:"url"`
						Network      string `json:"network"`
						NetworkName  string `json:"network_name"`
						SupportedURL string `json:"supported_url"`
					} `json:"x402"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode /sdk/domain response: %v", err)
			}
			if payload.Data.X402 == nil {
				t.Fatal("/sdk/domain response x402 object missing after decode")
			}
			if payload.Data.X402.Enabled != tc.wantEnabled {
				t.Fatalf("x402.enabled = %v, want %v", payload.Data.X402.Enabled, tc.wantEnabled)
			}
			if tc.wantEnabled {
				wantURL := tc.settings.PortalURL + pathX402Facilitator
				if payload.Data.X402.URL != wantURL {
					t.Fatalf("x402.url = %q, want %q", payload.Data.X402.URL, wantURL)
				}
				if payload.Data.X402.Network != "sui:testnet" || payload.Data.X402.NetworkName == "" || payload.Data.X402.SupportedURL != tc.settings.PortalURL+x402SupportedPath {
					t.Fatalf("x402 metadata = %+v, want testnet facilitator publication", payload.Data.X402)
				}
			}
		})
	}
}
