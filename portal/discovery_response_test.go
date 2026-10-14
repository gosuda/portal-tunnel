package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestWriteDiscoveryResponseRespectsByteBudget(t *testing.T) {
	t.Parallel()

	const selfURL = "https://self.example"
	response := types.DiscoveryResponse{
		ProtocolVersion: "discovery-v1",
		Relays: []types.RelayDescriptor{
			{APIHTTPSAddr: selfURL},
			{APIHTTPSAddr: "https://large.example", IVNPDestination: strings.Repeat("a", 650<<10)},
			{APIHTTPSAddr: "https://exceeds-budget.example", IVNPDestination: strings.Repeat("b", 650<<10)},
			{APIHTTPSAddr: "https://small.example"},
		},
		IncompatibleRelays: []types.IncompatibleRelayEntry{{URL: "https://old.example", ProtocolVersion: "v0"}},
		RelayReleaseVersions: map[string]string{
			"https://small.example": "v2.6.0",
		},
	}
	rec := httptest.NewRecorder()
	writeDiscoveryResponse(rec, response)
	if rec.Code != http.StatusOK {
		t.Fatalf("writeDiscoveryResponse() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if int64(rec.Body.Len()) > types.MaxDiscoveryResponseBytes {
		t.Fatalf("discovery response size = %d, limit = %d", rec.Body.Len(), types.MaxDiscoveryResponseBytes)
	}
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid discovery envelope: %v", err)
	}
	if !envelope.OK || len(envelope.Data.Relays) != 3 || envelope.Data.Relays[0].APIHTTPSAddr != selfURL || envelope.Data.Relays[2].APIHTTPSAddr != "https://small.example" {
		t.Fatal("oversized peer hid the self descriptor or a smaller peer")
	}
	if len(envelope.Data.IncompatibleRelays) != 1 || envelope.Data.RelayReleaseVersions["https://small.example"] != "v2.6.0" {
		t.Fatal("small observation metadata was lost")
	}
}

func TestWriteDiscoveryResponseCapsCollections(t *testing.T) {
	t.Parallel()

	response := types.DiscoveryResponse{
		Relays:               make([]types.RelayDescriptor, types.MaxDiscoveryEntries+2),
		IncompatibleRelays:   make([]types.IncompatibleRelayEntry, types.MaxDiscoveryEntries+1),
		RelayReleaseVersions: make(map[string]string),
	}
	for i := range response.Relays {
		response.Relays[i] = types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("https://relay-%d.example", i)}
	}
	for i := range response.IncompatibleRelays {
		response.IncompatibleRelays[i] = types.IncompatibleRelayEntry{URL: fmt.Sprintf("https://old-%d.example", i)}
	}
	for i := range types.MaxDiscoveryEntries + 1 {
		response.RelayReleaseVersions[fmt.Sprintf("https://observed-%d.example", i)] = "v"
	}

	rec := httptest.NewRecorder()
	writeDiscoveryResponse(rec, response)
	if rec.Code != http.StatusOK {
		t.Fatalf("writeDiscoveryResponse() status = %d", rec.Code)
	}
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid bounded discovery envelope: %v", err)
	}
	if len(envelope.Data.Relays) != types.MaxDiscoveryEntries+1 ||
		len(envelope.Data.IncompatibleRelays) != types.MaxDiscoveryEntries ||
		len(envelope.Data.RelayReleaseVersions) != types.MaxDiscoveryEntries {
		t.Fatalf("collection sizes = (%d, %d, %d), want (%d, %d, %d)",
			len(envelope.Data.Relays), len(envelope.Data.IncompatibleRelays), len(envelope.Data.RelayReleaseVersions),
			types.MaxDiscoveryEntries+1, types.MaxDiscoveryEntries, types.MaxDiscoveryEntries)
	}
}
