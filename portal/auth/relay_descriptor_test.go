package auth

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestVerifyRelayDescriptorRejectsFamilyCapabilityMutation(t *testing.T) {
	t.Parallel()

	signing, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	signed, err := SignRelayDescriptor(types.RelayDescriptor{
		Address:      signing.Address,
		Version:      types.DiscoveryVersion,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Hour),
		APIHTTPSAddr: "https://relay.example.com",
		SupportsIPv4: true,
		SupportsIPv6: false,
		SupportsUDP:  true,
		SupportsTCP:  true,
	}, signing.PrivateKey)
	if err != nil {
		t.Fatalf("SignRelayDescriptor() error = %v", err)
	}

	mutated := signed
	mutated.SupportsIPv6 = true

	if _, err := VerifyRelayDescriptor(mutated); err == nil {
		t.Fatal("VerifyRelayDescriptor() error = nil, want signature mismatch")
	}
}
