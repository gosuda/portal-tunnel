package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestOverlayAdmissionBindsSignedDestinationAndRejectsRotationRollback(t *testing.T) {
	signing := mustSigningIdentity(t)
	authority, err := identity.NewLocalAuthority(signing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desc := mustUnsignedDescriptor(t, signing, "https://overlay.example")
	desc.IVNPDestination = strings.Repeat("a", 52) + ".b32.i2p"
	desc.IssuedAt = now
	desc.ExpiresAt = now.Add(time.Minute)
	old, err := auth.SignRelayDescriptor(desc, authority)
	if err != nil {
		t.Fatal(err)
	}
	set := NewRelaySet(nil)
	if err := set.AdmitOverlayPeer(old); err != nil {
		t.Fatal(err)
	}
	tampered := old
	tampered.IVNPDestination = "b" + tampered.IVNPDestination[1:]
	if err := set.AdmitOverlayPeer(tampered); err == nil {
		t.Fatal("unsigned destination change accepted")
	}
	desc.IVNPDestination = tampered.IVNPDestination
	desc.IssuedAt = now.Add(time.Second)
	newer, err := auth.SignRelayDescriptor(desc, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.AdmitOverlayPeer(newer); err != nil {
		t.Fatal(err)
	}
	if err := set.AdmitOverlayPeer(old); err == nil {
		t.Fatal("old destination accepted after rotation")
	}
	if got := set.SelectRelays(RouteState{}); len(got) != 0 {
		t.Fatal("overlay admission promoted public ingress health")
	}
}

func TestOverlayRefreshHasIndependentCadenceAndHealth(t *testing.T) {
	signing := mustSigningIdentity(t)
	authority, err := identity.NewLocalAuthority(signing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desc := mustUnsignedDescriptor(t, signing, "https://overlay.example")
	desc.IVNPDestination = strings.Repeat("a", 52) + ".b32.i2p"
	desc.IssuedAt = now
	desc.ExpiresAt = now.Add(time.Minute)
	desc, err = auth.SignRelayDescriptor(desc, authority)
	if err != nil {
		t.Fatal(err)
	}
	set := NewRelaySet(nil)
	if err := set.InsertCandidate(desc, now); err != nil {
		t.Fatal(err)
	}
	set.RecordDiscoveryRTT(desc.APIHTTPSAddr, 20*time.Millisecond, now)
	before := set.currentRelayStates(now)[0]
	calls := 0
	refresh := NewRefresher(set)
	refresh.DiscoverOverlay = func(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error) {
		calls++
		return types.DiscoveryResponse{}, errors.New("overlay unavailable")
	}
	if err := refresh.refreshOverlay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := refresh.refreshOverlay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("overlay polls=%d, want cached cadence", calls)
	}
	after := set.currentRelayStates(now)[0]
	if after.DiscoveryRTT != before.DiscoveryRTT || after.discoveryFailures != before.discoveryFailures || after.Trust != before.Trust {
		t.Fatal("overlay failure changed public health")
	}
}
