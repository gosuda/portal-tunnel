package overlay

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestCapabilityRejectsExpiredCapability(t *testing.T) {
	t.Parallel()
	ingressAuthority := testAuthority(t, "ingress")
	gatewayAuthority := testAuthority(t, "gateway")
	ingress := testDescriptor(t, ingressAuthority, "https://ingress.example", testDestination("ingress"), 0)
	now := time.Now().UTC()
	valid := capabilityClaims{
		Version:            1,
		LeaseIdentity:      types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address},
		LeaseID:            "lease_1",
		ExpiresAt:          now.Add(time.Minute).Truncate(time.Second),
		Ingress:            ingress,
		GatewayAddress:     gatewayAuthority.Identity().Address,
		GatewayDestination: testDestination("gateway"),
	}
	capability, err := signCapability(ingressAuthority, valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCapability(capability, now); err != nil {
		t.Fatal(err)
	}
	expired := valid
	expired.ExpiresAt = now.Add(-time.Minute).Truncate(time.Second)
	expiredCapability, err := signCapability(ingressAuthority, expired)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCapability(expiredCapability, now); !errors.Is(err, errOverlayCapabilityExpiredOrIncomplete) {
		t.Fatalf("expired capability err = %v", err)
	}
}

func TestCapabilityRejectsWrongPrefix(t *testing.T) {
	t.Parallel()
	ingressAuthority := testAuthority(t, "ingress")
	gatewayAuthority := testAuthority(t, "gateway")
	ingress := testDescriptor(t, ingressAuthority, "https://ingress.example", testDestination("ingress"), 0)
	now := time.Now().UTC()
	claims := capabilityClaims{
		Version:            1,
		LeaseIdentity:      types.Identity{Name: "lease", Address: ingressAuthority.Identity().Address},
		LeaseID:            "lease_1",
		ExpiresAt:          now.Add(time.Minute).Truncate(time.Second),
		Ingress:            ingress,
		GatewayAddress:     gatewayAuthority.Identity().Address,
		GatewayDestination: testDestination("gateway"),
	}
	capability, err := signCapability(ingressAuthority, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCapability(capability, now); err != nil {
		t.Fatal(err)
	}
	wrong := strings.Replace(capability, types.OverlayCapabilityPrefix+".", "ov9.", 1)
	if _, err := verifyCapability(wrong, now); !errors.Is(err, errInvalidOverlayCapability) {
		t.Fatalf("wrong prefix capability err = %v", err)
	}
}
