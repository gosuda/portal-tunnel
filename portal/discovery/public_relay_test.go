package discovery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
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

// The first response simulates a reachable public HTTPS relay. Redirects to
// the real internal HTTP server must be rejected before its first request.
type redirectFromPublicRelay struct {
	target         string
	publicRequests *atomic.Int32
}

func (r redirectFromPublicRelay) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() == "relay-public.example" {
		r.publicRequests.Add(1)
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{r.target}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestUntrustedDiscoveryRejectsRedirectToInternalService(t *testing.T) {
	var internalRequests atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	set := NewRelaySet(nil)
	now := time.Now().UTC().Truncate(time.Microsecond)
	desc := mustRelayDescriptor(t, "https://relay-public.example")
	if err := set.InsertCandidate(desc, now); err != nil {
		t.Fatalf("InsertCandidate() error = %v", err)
	}
	refresher := NewRefresher(set)
	defer refresher.httpClient.CloseIdleConnections()
	defer refresher.publicHTTPClient.CloseIdleConnections()
	var publicRequests atomic.Int32
	refresher.publicHTTPClient.Transport = redirectFromPublicRelay{
		target:         internal.URL,
		publicRequests: &publicRequests,
	}

	if err := refresher.refreshOneHTTPS(context.Background(), relayStates(set)[0]); err != nil {
		t.Fatalf("refreshOneHTTPS() error = %v", err)
	}
	if got := publicRequests.Load(); got != 1 {
		t.Fatalf("public relay received %d requests, want one", got)
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
