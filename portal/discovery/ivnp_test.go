package discovery

import (
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestIVNPAdmissionAndSelection(t *testing.T) {
	set := NewRelaySet(nil)
	descriptors := make([]types.RelayDescriptor, 2)
	for i := range descriptors {
		signing := mustSigningIdentity(t)
		authority, err := identity.NewLocalAuthority(signing)
		if err != nil {
			t.Fatal(err)
		}
		desc := mustUnsignedDescriptor(t, signing, "https://"+string(rune('a'+i))+".example")
		desc.IVNPDestination = strings.Repeat(string(rune('a'+i)), 51) + "a.b32.i2p"
		desc, err = auth.SignRelayDescriptor(desc, authority)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.InsertCandidate(desc, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := set.IVNPRelay(desc.IVNPDestination); err == nil {
			t.Fatal("candidate admitted as IVNP peer")
		}
		mustApplyAuthoritative(t, set, desc)
		if _, err := set.IVNPRelay(desc.IVNPDestination); err != nil {
			t.Fatal(err)
		}
		descriptors[i] = desc
		forged := desc
		forged.IVNPDestination = strings.Repeat("c", 51) + "a.b32.i2p"
		if _, err := auth.VerifyRelayDescriptor(forged); err == nil {
			t.Fatal("unsigned destination substitution accepted")
		}
	}
	state := RouteState{IVNP: true, ExplicitRelayURLs: []string{descriptors[0].APIHTTPSAddr}, LocalAddress: "tenant"}
	routes := set.SelectRelays(state)
	if len(routes) == 0 || routes[0].GatewayURL != descriptors[1].APIHTTPSAddr || routes[0].IngressDestination != descriptors[0].IVNPDestination {
		t.Fatalf("selected endpoints: %+v", routes)
	}
	state.IVNP = false
	if routes := set.SelectRelays(state); len(routes) == 0 || routes[0].GatewayURL != "" {
		t.Fatalf("direct selection changed: %+v", routes)
	}
	state.IVNP = true
	set.DropRelayURLFromActivePool(descriptors[1].APIHTTPSAddr)
	if _, err := set.IVNPRelay(descriptors[1].IVNPDestination); err == nil {
		t.Fatal("banned gateway admitted")
	}
	if routes := set.SelectRelays(state); len(routes) != 0 {
		t.Fatalf("invalid gateway selection fell back: %+v", routes)
	}
}

func TestIVNPAdmissionUsesRollbackAnchor(t *testing.T) {
	set := NewRelaySet(nil)
	desc := mustRelayDescriptor(t, "https://old.example")
	// Install the same state an old URL retains after the signing identity
	// publishes a newer descriptor at a new URL.
	desc.IVNPDestination = strings.Repeat("a", 52) + ".b32.i2p"
	set.relays[desc.APIHTTPSAddr] = RelayState{Descriptor: desc, Trust: RelayVerified}
	set.keyIndex[strings.ToLower(desc.Address)] = keyIndexEntry{IssuedAt: desc.IssuedAt.Add(time.Second)}
	if _, err := set.IVNPRelay(desc.IVNPDestination); err == nil {
		t.Fatal("superseded destination admitted")
	}
}
