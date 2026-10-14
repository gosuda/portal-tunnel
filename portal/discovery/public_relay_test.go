package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestPublicRelayIPPolicy(t *testing.T) {
	tests := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"2001:4860:4860::8888", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"0.0.0.1", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"::ffff:127.0.0.1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"2001::1", false},
		{"2002:c0a8:101::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isPublicRelayIP(netip.MustParseAddr(tt.ip)); got != tt.public {
				t.Fatalf("isPublicRelayIP(%q) = %t, want %t", tt.ip, got, tt.public)
			}
		})
	}
}

func TestUntrustedDiscoveryRejectsNonPublicDescriptor(t *testing.T) {
	signing := mustSigningIdentity(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, relayURL := range []string{
		"https://localhost",
		"https://sub.localhost",
		"https://relay.local",
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://100.64.0.1",
		"https://169.254.169.254",
		"https://192.0.2.1",
		"https://198.18.0.1",
		"https://[::1]",
		"https://[::ffff:127.0.0.1]",
		"https://[2001:db8::1]",
	} {
		t.Run(relayURL, func(t *testing.T) {
			desc := mustSignedDescriptor(t, signing, relayURL, now)

			announced := NewRelaySet(nil)
			if err := announced.InsertCandidate(desc, now); err == nil {
				t.Fatal("non-public announced descriptor accepted")
			}
			if states := relayStates(announced); len(states) != 0 {
				t.Fatalf("announced candidates = %v, want none", states)
			}

			gossiped := NewRelaySet(nil)
			changed, err := gossiped.ApplyRelayDiscoveryResponse("", types.DiscoveryResponse{
				ProtocolVersion: types.DiscoveryVersion,
				Relays:          []types.RelayDescriptor{desc},
			}, now)
			if err != nil {
				t.Fatalf("ApplyRelayDiscoveryResponse() error = %v", err)
			}
			if changed || len(relayStates(gossiped)) != 0 {
				t.Fatal("non-public gossiped descriptor admitted into refresh state")
			}
		})
	}
}

func TestExplicitBootstrapAcceptsOwnLocalDescriptor(t *testing.T) {
	const relayURL = "https://127.0.0.1:39393"
	set := NewRelaySet([]string{relayURL})
	desc := mustRelayDescriptor(t, relayURL)
	if _, err := set.ApplyRelayDiscoveryResponse(relayURL, types.DiscoveryResponse{
		ProtocolVersion: types.DiscoveryVersion,
		Relays:          []types.RelayDescriptor{desc},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("configured localhost bootstrap rejected: %v", err)
	}
	states := relayStates(set)
	if len(states) != 1 || states[0].Trust != RelayVerified {
		t.Fatalf("bootstrap states = %v, want verified local relay", states)
	}
}

func TestPublicRelayDialRejectsResolvedLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, address := range []string{"localhost:443", "127.0.0.1:443", "[::1]:443"} {
		conn, err := dialPublicRelay(ctx, "tcp", address)
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("dialPublicRelay(%q) connected to loopback", address)
		}
		if err == nil {
			t.Fatalf("dialPublicRelay(%q) accepted loopback", address)
		}
	}
}

func TestDiscoveryRedirectPolicyRejectsInternalService(t *testing.T) {
	var internalRequests atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, internal.URL, http.StatusFound)
	}))
	defer source.Close()
	client := &http.Client{CheckRedirect: rejectDiscoveryRedirect, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(source.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp == nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect response = %v, error = %v", resp, err)
	}
	if err == nil {
		t.Fatal("discovery redirect was accepted")
	}
	if got := internalRequests.Load(); got != 0 {
		t.Fatalf("internal service received %d redirected requests, want zero", got)
	}
}

func TestLocalBootstrapDiscoveryRejectsRedirect(t *testing.T) {
	var internalRequests atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()
	var bootstrapRequests atomic.Int32
	bootstrap := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bootstrapRequests.Add(1)
		http.Redirect(w, req, internal.URL, http.StatusFound)
	}))
	defer bootstrap.Close()

	set := NewRelaySet([]string{bootstrap.URL})
	refresher := NewRefresher(set)
	defer refresher.httpClient.CloseIdleConnections()
	defer refresher.publicHTTPClient.CloseIdleConnections()
	if err := refresher.refreshOneHTTPS(context.Background(), bootstrapRelayState(bootstrap.URL)); err != nil {
		t.Fatalf("refreshOneHTTPS() error = %v", err)
	}
	if got := bootstrapRequests.Load(); got != 1 {
		t.Fatalf("bootstrap received %d requests, want one", got)
	}
	if got := internalRequests.Load(); got != 0 {
		t.Fatalf("internal service received %d redirected bootstrap requests, want zero", got)
	}
}
