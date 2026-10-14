package sdk

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAliasURLForLeaseRequiresGrantedAlias(t *testing.T) {
	t.Parallel()

	relayURL, err := url.Parse("https://relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{api: &apiClient{relayURL: relayURL}}
	const canonical = "demo-0123456789abcdef0123456789abcdef01234567.relay.example.com"

	granted := listenerSnapshot{hostname: canonical, aliasHostname: "demo.relay.example.com"}
	if got, want := l.aliasURLForLease(granted), "https://demo.relay.example.com:443"; got != want {
		t.Fatalf("aliasURLForLease(granted) = %q, want %q", got, want)
	}
	if got, want := l.publicURLForLease(granted), "https://"+canonical+":443"; got != want {
		t.Fatalf("publicURLForLease(granted) = %q, want canonical %q", got, want)
	}
	if got := l.aliasURLForLease(listenerSnapshot{hostname: canonical}); got != "" {
		t.Fatalf("aliasURLForLease(fallback) = %q, want empty", got)
	}
}

func TestPublicURLForLeaseUsesRelayAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		relayURL string
		want     string
	}{
		{"default HTTPS port", "https://relay.example.com", "https://demo.relay.example.com:443"},
		{"explicit default port", "https://relay.example.com:443", "https://demo.relay.example.com:443"},
		{"explicit public port", "https://relay.example.com:9443", "https://demo.relay.example.com:9443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			relayURL, err := url.Parse(tc.relayURL)
			if err != nil {
				t.Fatal(err)
			}
			l := &listener{api: &apiClient{relayURL: relayURL}}
			got := l.publicURLForLease(listenerSnapshot{
				hostname: "demo.relay.example.com",
			})
			if got != tc.want {
				t.Fatalf("publicURLForLease() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExposeRejectsIncompleteIdentity(t *testing.T) {
	_, err := Expose(context.Background(), types.Identity{Name: "svc"}, []string{"https://relay.example"})
	if err == nil || !strings.Contains(err.Error(), "identity must include") {
		t.Fatalf("Expose() error = %v, want incomplete identity error", err)
	}
}

func TestExposeRejectsEmptyInitialRelays(t *testing.T) {
	for _, name := range []string{"svc", ""} {
		identity := types.Identity{
			Name:       name,
			Address:    "address",
			PublicKey:  "public",
			PrivateKey: "private",
		}
		for _, relays := range [][]string{nil, {}} {
			_, err := Expose(context.Background(), identity, relays)
			if err == nil || !strings.Contains(err.Error(), "at least one initial relay") {
				t.Fatalf("Expose(name=%q, %v) error = %v, want initial relay error", name, relays, err)
			}
		}
	}
}

func TestExposeOptionsContainOnlyEndpointCapabilities(t *testing.T) {
	metadata := types.LeaseMetadata{Tags: []string{"initial"}}
	var got options
	for _, option := range []Option{
		WithUDP(),
		WithTCP(),
		WithMITMProtection(true),
		WithOverlay(),
		WithMetadata(metadata),
	} {
		option(&got)
	}
	metadata.Tags[0] = "mutated"
	if !got.UDPEnabled || !got.TCPEnabled || !got.BanMITM || !got.Overlay {
		t.Fatalf("options = %+v, want all endpoint capabilities enabled", got)
	}
	if got.Metadata.Tags[0] != "initial" {
		t.Fatalf("metadata tags = %v, want copied initial value", got.Metadata.Tags)
	}
}

func TestExposeRejectsNilOption(t *testing.T) {
	_, err := Expose(context.Background(), types.Identity{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "option is nil") {
		t.Fatalf("Expose() error = %v, want nil option error", err)
	}
}

func TestProxyValidationDoesNotCloseExposure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	exposure := &Exposure{
		cancel:         cancel,
		done:           ctx.Done(),
		accepted:       make(chan net.Conn, 1),
		relayListeners: make(map[string]*listener),
	}
	if err := ProxyWithConfig(ctx, exposure, ProxyConfig{}); err == nil {
		t.Fatal("ProxyWithConfig() succeeded without a target")
	}
	select {
	case <-ctx.Done():
		t.Fatal("ProxyWithConfig() closed exposure during validation")
	default:
	}
	_ = exposure.Close()
}

func TestExposureMetadataCopiesDoNotShareMutableState(t *testing.T) {
	ln := &listener{
		metadata: types.LeaseMetadata{Tags: []string{"initial"}},
	}
	exposure := &Exposure{
		metadata:       types.LeaseMetadata{Tags: []string{"initial"}},
		relayListeners: map[string]*listener{"https://relay.example": ln},
	}
	metadata := exposure.metadata.Copy()
	metadata.Tags[0] = "mutated"
	if got := exposure.metadata.Tags[0]; got != "initial" {
		t.Fatalf("Metadata.Tags[0] = %q, want initial", got)
	}
	if err := exposure.UpdateMetadata(types.LeaseMetadata{Tags: []string{"updated"}}); err != nil {
		t.Fatalf("UpdateMetadata() error = %v", err)
	}
	if got := ln.metadataSnapshot().Tags[0]; got != "updated" {
		t.Fatalf("listener Metadata.Tags[0] = %q, want updated", got)
	}
}

func testIdentity() types.Identity {
	return types.Identity{
		Name:       "svc",
		Address:    "address",
		PublicKey:  "public",
		PrivateKey: "private",
	}
}

func TestExposeWithDiscoveryRetainsExplicitRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{"https://relay.example"}, WithDiscovery(1))
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// The explicit relay must appear in the membership. Its listener starts
	// in RelayConnecting and will eventually fail (unreachable), but it is
	// retained because explicit relays are always kept by the discovery
	// selection. No network assertions: we only check membership presence.
	relays := exposure.Relays()
	found := false
	for _, r := range relays {
		if r.RelayURL == "https://relay.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Relays() = %+v, want https://relay.example present", relays)
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestExposeDiscoveryStaysUsableAfterRelayFailure(t *testing.T) {
	const (
		relayA = "https://relay-a.example"
		relayB = "https://relay-b.example"
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{relayA, relayB}, WithDiscovery(2))
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// Force one relay to fail. The failure hook reports it to the
	// discovery controller, which unconfirms and suppresses it. The
	// other relay must remain in the membership — the exposure stays
	// usable. We drive the failure the same way existing failure tests
	// do: via setRelayStatus.
	exposure.setRelayStatus(relayA, listenerStatus{
		state: RelayFailed,
		err:   errors.New("rejected"),
	})

	// relayB is an explicit relay present in the membership from
	// construction, so the exposure stays usable after the failure; the
	// discovery reaction (unconfirm + suppression → re-selection) is
	// covered by the discovery package tests. setRelayStatus exercised
	// the synchronous failure→discovery.Report hook above. The failed
	// relay's own status is not asserted because the listener retry loop
	// flips it between failed and connecting asynchronously.
	relays := exposure.Relays()
	var foundA, foundB bool
	for _, r := range relays {
		switch r.RelayURL {
		case relayA:
			foundA = true
		case relayB:
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("Relays() = %+v, want %s and %s present after failure", relays, relayA, relayB)
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestExposeSetMaxActiveRelaysNoDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exposure, err := Expose(ctx, testIdentity(), []string{"https://relay.example"})
	if err != nil {
		t.Fatalf("Expose() error = %v", err)
	}
	defer func() { _ = exposure.Close() }()

	// Without discovery, SetMaxActiveRelays is a no-op that returns nil.
	if err := exposure.SetMaxActiveRelays(1); err != nil {
		t.Fatalf("SetMaxActiveRelays(1) error = %v, want nil", err)
	}
}
