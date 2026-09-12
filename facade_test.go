package portal

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestAssembleExposeConfigMapsFacadeAndOptions(t *testing.T) {
	cfg := ExposeConfig{
		Relays:     []string{"https://relay.example"},
		Identity:   types.Identity{Name: "svc", Address: "0xabc"},
		UDPEnabled: true,
	}
	settings := exposeSettings{
		discovery:       true,
		overlay:         true,
		ech:             true,
		banMITM:         true,
		rawTCP:          true,
		maxActiveRelays: 3,
		metadata:        types.LeaseMetadata{Description: "demo"},
	}

	got := assembleExposeConfig(cfg, settings)

	want := sdk.ExposeConfig{
		RelayURLs:       []string{"https://relay.example"},
		Discovery:       true,
		Overlay:         true,
		Identity:        types.Identity{Name: "svc", Address: "0xabc"},
		UDPEnabled:      true,
		TCPEnabled:      true,
		ECH:             true,
		BanMITM:         true,
		MaxActiveRelays: 3,
		Metadata:        types.LeaseMetadata{Description: "demo"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assembled config mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.TargetAddr != "" || got.UDPAddr != "" || got.IdentityPath != "" || got.IdentityJSON != "" {
		t.Fatalf("proxy targets and identity persistence must not leak into the facade config: %+v", got)
	}
	if got.X402PayTo != "" {
		t.Fatalf("x402 application policy must not leak into the facade config: %+v", got)
	}
}

func TestExposeOptionMapping(t *testing.T) {
	var settings exposeSettings
	for _, opt := range []ExposeOption{
		WithDiscovery(),
		WithOverlay(),
		WithECH(),
		WithBanMITM(),
		WithRawTCP(),
		WithMaxActiveRelays(4),
		WithMaxActiveRelays(0),
		WithMetadata(types.LeaseMetadata{Owner: "me"}),
	} {
		opt(&settings)
	}

	if !settings.discovery || !settings.overlay || !settings.ech || !settings.banMITM || !settings.rawTCP {
		t.Fatalf("bool options did not apply: %+v", settings)
	}
	if settings.maxActiveRelays != 4 {
		t.Fatalf("WithMaxActiveRelays: got %d, want 4 (values below 1 must keep the previous value)", settings.maxActiveRelays)
	}
	if settings.metadata.Owner != "me" {
		t.Fatalf("WithMetadata did not apply: %+v", settings.metadata)
	}
}

func TestExposeRejectsMissingInputs(t *testing.T) {
	ctx := context.Background()

	// A nil-valued context (rather than a nil literal) exercises the guard
	// without tripping SA1012.
	var nilCtx context.Context
	if _, err := Expose(nilCtx, ExposeConfig{Identity: types.Identity{Name: "svc"}, Relays: DefaultRelays()}); !errors.Is(err, errNilContext) {
		t.Fatalf("nil context: got %v, want %v", err, errNilContext)
	}
	if _, err := Expose(ctx, ExposeConfig{Relays: DefaultRelays()}); err == nil || err.Error() != "portal: identity is required" {
		t.Fatalf("missing identity: got %v", err)
	}
	identity := types.Identity{Name: "svc"}
	if _, err := Expose(ctx, ExposeConfig{Identity: identity}); err == nil || err.Error() != "portal: at least one relay is required" {
		t.Fatalf("missing relays: got %v", err)
	}
}

func TestRelayStatusesFromSnapshotMapsStatesSorted(t *testing.T) {
	snapshot := types.AgentTunnelStatus{
		Relays: []types.AgentRelayStatus{
			{RelayURL: "https://b.example", Connecting: true},
			{RelayURL: "https://c.example", Banned: true},
			{RelayURL: "https://a.example", PublicURL: "https://svc.a.example"},
		},
	}

	statuses := relayStatusesFromSnapshot(snapshot)

	if len(statuses) != 3 {
		t.Fatalf("got %d statuses, want 3", len(statuses))
	}
	if statuses[0].RelayURL != "https://a.example" || statuses[0].State != RelayReady || statuses[0].PublicURL != "https://svc.a.example" {
		t.Fatalf("ready relay mapped wrong: %+v", statuses[0])
	}
	if statuses[1].RelayURL != "https://b.example" || statuses[1].State != RelayConnecting {
		t.Fatalf("connecting relay mapped wrong: %+v", statuses[1])
	}
	if statuses[2].RelayURL != "https://c.example" || statuses[2].State != RelayFailed {
		t.Fatalf("banned relay mapped wrong: %+v", statuses[2])
	}
}

func TestRelayStatusHelpers(t *testing.T) {
	statuses := []RelayStatus{
		{RelayURL: "a", State: RelayReady},
		{RelayURL: "b", State: RelayUDPReady},
		{RelayURL: "c", State: RelayConnecting},
	}
	if got := readyStatuses(statuses); len(got) != 2 {
		t.Fatalf("readyStatuses: got %d, want 2", len(got))
	}
	if allFailed(statuses) {
		t.Fatal("allFailed must be false while any relay is not failed")
	}
	if !allFailed([]RelayStatus{{RelayURL: "a", State: RelayFailed}, {RelayURL: "b", State: RelayFailed}}) {
		t.Fatal("allFailed must be true when every relay failed")
	}
	if !relayStatusUnchanged(statuses[0], statuses[0]) {
		t.Fatal("identical statuses must compare unchanged")
	}
	changed := statuses[0]
	changed.State = RelayFailed
	if relayStatusUnchanged(statuses[0], changed) {
		t.Fatal("state change must be detected")
	}
}

func TestDefaultRelaysIsStableSnapshot(t *testing.T) {
	first := DefaultRelays()
	if len(first) == 0 {
		t.Fatal("DefaultRelays returned no relays")
	}
	first[0] = "https://mutated.example"
	if second := DefaultRelays(); second[0] == "https://mutated.example" {
		t.Fatalf("DefaultRelays leaks internal state: %v", second)
	}
	if !reflect.DeepEqual(DefaultRelays(), DefaultRelays()) {
		t.Fatal("DefaultRelays is not deterministic")
	}
}
func TestProxyWithConfigValidation(t *testing.T) {
	if err := ProxyWithConfig(context.Background(), nil, ProxyConfig{TCPTarget: "127.0.0.1:8080"}); err == nil {
		t.Fatal("nil exposure must be rejected")
	}
	exposure := &Exposure{inner: &sdk.Exposure{}}
	if err := ProxyWithConfig(context.Background(), exposure, ProxyConfig{}); err == nil || err.Error() != "portal: at least one proxy target is required" {
		t.Fatalf("empty targets: got %v", err)
	}
}

// Example demonstrates the issue #400 usage shape: Expose returns a virtual
// listener an http.Server can serve directly, while relay readiness and
// proxying stay separate concerns.
func Example() {
	identity, err := GenerateIdentity("my-app")
	if err != nil {
		return
	}
	listener, err := Expose(context.Background(), ExposeConfig{
		Identity: identity,
		Relays:   DefaultRelays(),
	}, WithMaxActiveRelays(3))
	if err != nil {
		return
	}
	defer listener.Close()

	ready, err := listener.WaitReady(context.Background())
	if err != nil {
		return
	}
	_ = ready

	go func() { _ = Proxy(context.Background(), listener, "127.0.0.1:8080") }()
}

var _ net.Listener = (*Exposure)(nil)
