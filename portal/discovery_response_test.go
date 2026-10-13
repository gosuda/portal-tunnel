package portal

import (
	"encoding/json"
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
			{APIHTTPSAddr: "https://" + strings.Repeat("a", 650<<10)},
			{APIHTTPSAddr: "https://" + strings.Repeat("b", 650<<10)},
		},
		RelayReleaseVersions: map[string]string{
			"https://peer-1.example": strings.Repeat("v", 600<<10),
			"https://peer-2.example": strings.Repeat("v", 600<<10),
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
	if !envelope.OK || len(envelope.Data.Relays) == 0 || envelope.Data.Relays[0].APIHTTPSAddr != selfURL {
		t.Fatalf("discovery response omitted the serving relay: %+v", envelope.Data)
	}
}

func TestWriteDiscoveryResponsePreservesSmallMetadata(t *testing.T) {
	t.Parallel()

	response := types.DiscoveryResponse{
		ProtocolVersion: "discovery-v1",
		Relays: []types.RelayDescriptor{{APIHTTPSAddr: "https://self.example"}},
		IncompatibleRelays: []types.IncompatibleRelayEntry{{URL: "https://old.example", ProtocolVersion: "v0"}},
		RelayReleaseVersions: map[string]string{"https://peer.example": "v2.6.0"},
	}
	rec := httptest.NewRecorder()
	writeDiscoveryResponse(rec, response)
	if rec.Code != http.StatusOK {
		t.Fatalf("writeDiscoveryResponse() status = %d, want %d", rec.Code, http.StatusOK)
	}
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Relays) != 1 || len(envelope.Data.IncompatibleRelays) != 1 ||
		envelope.Data.RelayReleaseVersions["https://peer.example"] != "v2.6.0" {
		t.Fatalf("expected complete bounded response, got %+v", envelope.Data)
	}
}
