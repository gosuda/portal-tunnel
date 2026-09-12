package sdk

import (
	"context"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/internal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestExposeOptionsMapToSDKConfig(t *testing.T) {
	cfg := ExposeConfig{RelayURLs: []string{"https://relay.example"}}
	WithDiscovery()(&cfg)
	WithOverlay()(&cfg)
	WithECH()(&cfg)
	WithBanMITM()(&cfg)
	WithRawTCP()(&cfg)
	WithMaxActiveRelays(3)(&cfg)
	WithMetadata(types.LeaseMetadata{Owner: "me"})(&cfg)

	if !cfg.Discovery || !cfg.Overlay || !cfg.ECH || !cfg.BanMITM || !cfg.TCPEnabled {
		t.Fatalf("options did not apply: %+v", cfg)
	}
	if cfg.MaxActiveRelays != 3 || cfg.Metadata.Owner != "me" {
		t.Fatalf("options mapped incorrectly: %+v", cfg)
	}
}

func TestDefaultRelaysReturnsIndependentSnapshot(t *testing.T) {
	first := DefaultRelays()
	if len(first) == 0 {
		t.Fatal("DefaultRelays returned no relays")
	}
	first[0] = "https://mutated.example"
	if second := DefaultRelays(); second[0] == first[0] {
		t.Fatalf("DefaultRelays leaked internal state: %v", second)
	}
}

func TestExposeRejectsUnresolvedIdentity(t *testing.T) {
	_, err := Expose(context.Background(), ExposeConfig{
		RelayURLs: []string{"https://relay.example"},
		Identity:  types.Identity{Name: "service"},
	})
	if err == nil || !strings.Contains(err.Error(), "resolved identity is required") {
		t.Fatalf("Expose error = %v, want unresolved identity error", err)
	}
}

func TestExposeRejectsNilContext(t *testing.T) {
	var ctx context.Context
	_, err := Expose(ctx, ExposeConfig{})
	if !errors.Is(err, errNilContext) {
		t.Fatalf("Expose(nil): got %v, want %v", err, errNilContext)
	}
}

func TestRelayStatusUsesListenerRuntime(t *testing.T) {
	relayURL := "https://relay.example"
	parsed, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	listener := &listener{
		relayURL: parsed,
		route:    discovery.Route{RelayURL: relayURL},
		lease: utils.NewSnapshot(listenerSnapshot{
			accessToken:   "token",
			hostname:      "service.example",
			publicURLBase: parsed,
			tcpAddr:       "127.0.0.1:443",
		}, listenerSnapshot.snapshot),
	}

	got := relayStatusFromListener(listener)
	want := RelayStatus{RelayURL: relayURL, PublicURL: "https://service.example", State: RelayReady}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("relayStatusFromListener() = %+v, want %+v", got, want)
	}
}

func TestWaitReadyReturnsTerminalFailure(t *testing.T) {
	exposure := &Exposure{
		done: make(chan struct{}),
		statuses: map[string]RelayStatus{
			"https://relay.example": {RelayURL: "https://relay.example", State: RelayFailed},
		},
	}

	_, err := exposure.WaitReady(context.Background())
	if !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitReady() error = %v, want %v", err, ErrNoRelays)
	}
}

func TestUpdatesReplaysAndCloses(t *testing.T) {
	exposure := &Exposure{
		done: make(chan struct{}),
		statuses: map[string]RelayStatus{
			"https://relay.example": {RelayURL: "https://relay.example", State: RelayConnecting},
		},
	}

	updates := exposure.Updates()
	select {
	case status := <-updates:
		if status.RelayURL != "https://relay.example" {
			t.Fatalf("replayed status = %+v", status)
		}
	default:
		t.Fatal("Updates did not replay current status")
	}

	_ = exposure.Close()
	if _, ok := <-updates; ok {
		t.Fatal("Updates channel remained open after Close")
	}
}

var _ net.Listener = (*Exposure)(nil)
