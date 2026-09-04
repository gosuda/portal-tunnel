package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNormalizeRelayDescriptorAcceptsIVNPOverlay(t *testing.T) {
	now := time.Now().UTC()
	descriptor, err := NormalizeRelayDescriptor(types.RelayDescriptor{
		Address:         "0x0000000000000000000000000000000000000001",
		Version:         types.DiscoveryVersion,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
		APIHTTPSAddr:    "https://relay.example",
		IVNPDestination: strings.Repeat("a", 52) + ".B32.I2P",
		SupportsOverlay: true,
	})
	if err != nil {
		t.Fatalf("NormalizeRelayDescriptor() error = %v", err)
	}
	if !descriptor.HasIVNPPeer() || !descriptor.HasOverlayPeer() {
		t.Fatal("normalized descriptor does not expose its IVNP overlay capability")
	}
	if descriptor.IVNPDestination != strings.Repeat("a", 52)+".b32.i2p" {
		t.Fatalf("IVNPDestination = %q", descriptor.IVNPDestination)
	}
}

func TestNormalizeRelayDescriptorRejectsInvalidIVNPDestination(t *testing.T) {
	now := time.Now().UTC()
	_, err := NormalizeRelayDescriptor(types.RelayDescriptor{
		Address:         "0x0000000000000000000000000000000000000001",
		Version:         types.DiscoveryVersion,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
		APIHTTPSAddr:    "https://relay.example",
		IVNPDestination: "not-a-destination.b32.i2p",
		SupportsOverlay: true,
	})
	if err == nil {
		t.Fatal("NormalizeRelayDescriptor() error = nil")
	}
}
