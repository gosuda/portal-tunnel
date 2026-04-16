package sdk

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestBuildMultiHopPath(t *testing.T) {
	relayURLs := []string{
		"https://relay-1.example",
		"https://relay-2.example",
		"https://relay-3.example",
		"https://relay-4.example",
		"https://relay-5.example",
		"https://relay-6.example",
	}

	set := discovery.NewRelaySet(relayURLs)
	now := time.Now()
	for _, u := range relayURLs {
		identity, _ := utils.ResolveSecp256k1Identity("")
		identity.Name = u
		desc := types.RelayDescriptor{
			Identity:            identity,
			RelayID:             u,
			OwnerAddress:        identity.Address,
			Version:             1,
			IssuedAt:            now,
			ExpiresAt:           now.Add(time.Hour),
			APIHTTPSAddr:        u,
			WireGuardPublicKey:  "pub-" + u,
			WireGuardEndpoint:   u + ":51820",
			OverlayIPv4:         "10.0.0." + u[14:15],
			SupportsOverlayPeer: true,
			Discovery:           true,
		}
		signedDesc, err := auth.SignRelayDescriptor(desc, identity.PrivateKey)
		if err != nil {
			t.Fatalf("SignRelayDescriptor error: %v", err)
		}
		_ = set.InsertAnnounced(signedDesc, now)
	}

	exposure := &Exposure{
		identity:    types.Identity{Name: "sdk-client", Address: "0xSDK"},
		relaySet:    set,
		routePolicy: policy.NewRoutePolicy(),
	}

	ingressURL := relayURLs[0]
	allRelays := set.OverlayPeerStates()

	path := exposure.findMolsPath(ingressURL, allRelays)

	if len(path) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(path))
	}

	if path[0].Descriptor.APIHTTPSAddr != ingressURL {
		t.Fatalf("path[0] should be ingress, got %v", path[0].Descriptor.APIHTTPSAddr)
	}

	t.Logf("Built path: SDK -> %v -> %v -> %v", path[2].Descriptor.APIHTTPSAddr, path[1].Descriptor.APIHTTPSAddr, path[0].Descriptor.APIHTTPSAddr)
}
