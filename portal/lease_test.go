package portal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// signLeaseRequest builds the /v1/sign-shaped request the token gate reads.
func signLeaseRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com"+types.PathV1Sign, nil)
	if err != nil {
		t.Fatalf("build sign request: %v", err)
	}
	req.Header.Set(types.HeaderAccessToken, token)
	return req
}

func newTestRegistry(t *testing.T, udpEnabled, tcpPortEnabled bool) *leaseRegistry {
	t.Helper()
	minPort, maxPort := 0, 0
	if udpEnabled || tcpPortEnabled {
		minPort, maxPort = testPortRange(t, 2)
	}
	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	registry, err := newLeaseRegistry(minPort, maxPort, relay.Name, relayAuthority, "https://example.com")
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	registry.setUDPPolicy(udpEnabled, 0)
	registry.setTCPPortPolicy(tcpPortEnabled, 0)
	// Registered leases bind UDP and raw-TCP relays; releasing them keeps
	// repeated runs in one process free of port collisions.
	t.Cleanup(func() { registry.CloseAll() })
	return registry
}

func testPortRange(t *testing.T, size int) (int, int) {
	t.Helper()
	for range 100 {
		first, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
		if err != nil {
			t.Fatalf("reserve ephemeral TCP port: %v", err)
		}
		minPort := first.Addr().(*net.TCPAddr).Port
		maxPort := minPort + size - 1
		listeners := []io.Closer{first}
		available := maxPort <= 65535
		for port := minPort; available && port <= maxPort; port++ {
			if port != minPort {
				listener, listenErr := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
				if listenErr != nil {
					available = false
					break
				}
				listeners = append(listeners, listener)
			}
			packet, listenErr := net.ListenUDP("udp", &net.UDPAddr{Port: port})
			if listenErr != nil {
				available = false
				break
			}
			listeners = append(listeners, packet)
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if available {
			return minPort, maxPort
		}
	}
	t.Fatal("could not find an ephemeral port range for raw transport test")
	return 0, 0
}

func newTestLeaseIdentity(t *testing.T, name string) types.Identity {
	t.Helper()
	testIdentity, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("identity.ResolveSecp256k1Identity() error = %v", err)
	}
	testIdentity.Name = name
	return testIdentity
}

func TestRegisterOverlayPreferenceFallsBackToDirect(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "overlay-fallback"),
		Overlay:  true,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !record.Overlay {
		t.Fatal("Register() did not preserve overlay preference")
	}
	if registered.ReverseEndpoint.Overlay || registered.ReverseEndpoint.URL != registry.reverseURL {
		t.Fatalf("Register() reverse endpoint = %#v, want direct fallback", registered.ReverseEndpoint)
	}
}

func TestLeaseRegistryLifecycle(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "demo"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.ReverseEndpoint.URL != "https://example.com/sdk/connect" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("Register() reverse endpoint = %#v, want direct capability", resp.ReverseEndpoint)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || leases[0].Hostname != "demo.example.com" || leases[0].CanonicalHostname != resp.CanonicalHostname || leases[0].Address != resp.Identity.Address {
		t.Fatalf("PublicLeases() = %+v, want the registered demo lease", leases)
	}
	if resp.Hostname != "demo.example.com" || resp.CanonicalHostname == "" {
		t.Fatalf("RegisterResponse hostnames = (%q, %q), want friendly and canonical hostnames", resp.Hostname, resp.CanonicalHostname)
	}
	if _, ok := registry.Lookup(resp.CanonicalHostname); !ok {
		t.Fatal("Lookup(canonical hostname) = false, want registered lease")
	}

	renewed, endpointInput, err := registry.Renew(types.RenewRequest{
		AccessToken: resp.AccessToken,
		TTL:         600,
	}, netip.MustParseAddr("203.0.113.11"), nil)
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if !renewed.ExpiresAt.After(resp.ExpiresAt) {
		t.Fatalf("Renew() expires at = %v, want later than register expiry %v", renewed.ExpiresAt, resp.ExpiresAt)
	}
	if renewed.ExpiresAt.After(time.Now().Add(600 * time.Second)) {
		t.Fatalf("Renew() expiry exceeds the 600-second maximum: %v", renewed.ExpiresAt)
	}
	if _, err := registry.admitLeaseByToken(renewed.AccessToken, false); err != nil {
		t.Fatalf("admitLeaseByToken(renewed access token) error = %v, want admitted", err)
	}
	rotated, err := registry.issueReverseEndpoint(endpointInput, types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("issueReverseEndpoint() after Renew error = %v", err)
	}
	if rotated.Capability == "" || rotated.Capability == resp.ReverseEndpoint.Capability {
		t.Fatal("issueReverseEndpoint() did not rotate the reverse capability")
	}
	if _, err := registry.admitReverseCapability(rotated.Capability); err != nil {
		t.Fatalf("admitReverseCapability(rotated capability) error = %v, want admitted", err)
	}

	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: renewed.AccessToken}); err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
	if _, ok := registry.Lookup("demo.example.com"); ok {
		t.Fatal("Lookup() after Unregister() = true, want false")
	}
}

func TestLeaseRegistryTTLBounds(t *testing.T) {
	t.Parallel()
	for _, seconds := range []int{-1, 0, 600, 601, math.MaxInt} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			registry := newTestRegistry(t, false, false)
			request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "ttl"), TTL: seconds}
			_, challengeErr := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, netip.Addr{})
			started := time.Now().UTC().Truncate(time.Second)
			_, response, registerErr := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
			if seconds > 600 {
				if !errors.Is(challengeErr, errLeaseTTLExceeded) || !errors.Is(registerErr, errLeaseTTLExceeded) {
					t.Fatalf("oversized TTL: challenge error=%v, registration error=%v", challengeErr, registerErr)
				}
				if len(registry.records) != 0 {
					t.Fatal("rejected TTL retained a challenge or lease")
				}
				return
			}
			if challengeErr != nil || registerErr != nil {
				t.Fatalf("accepted TTL: challenge error=%v, registration error=%v", challengeErr, registerErr)
			}
			ttl := 120 * time.Second
			if seconds > 0 {
				ttl = time.Duration(seconds) * time.Second
			}
			if response.ExpiresAt.Before(started.Add(ttl)) || response.ExpiresAt.After(time.Now().Add(ttl)) {
				t.Fatalf("lease expiry=%v, want TTL %v", response.ExpiresAt, ttl)
			}
		})
	}
}

func TestLeaseRegistryInvalidRenewPreservesLease(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "invalid-renew"),
		TTL:      60,
		Metadata: types.LeaseMetadata{Description: "original", Tags: []string{"original"}},
	}, netip.MustParseAddr("203.0.113.10"), "198.51.100.10", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := registry.publicLease(record)
	beforeSource, beforeReported := record.sourceAddr, record.ReportedIP
	for _, request := range []types.RenewRequest{
		{TTL: 600, Metadata: types.LeaseMetadata{Description: strings.Repeat("a", 4097)}},
		{TTL: 601},
		{TTL: math.MaxInt},
	} {
		request.AccessToken = registered.AccessToken
		request.ReportedIP = "198.51.100.11"
		if _, _, err := registry.Renew(request, netip.MustParseAddr("203.0.113.11"), nil); err == nil {
			t.Fatal("Renew() accepted invalid metadata or TTL")
		}
		if after := registry.publicLease(record); !reflect.DeepEqual(after, before) {
			t.Fatalf("rejected Renew() changed lease: before=%+v after=%+v", before, after)
		}
		if record.sourceAddr != beforeSource || record.ReportedIP != beforeReported {
			t.Fatal("rejected Renew() changed source or reported IP")
		}
	}
}

func TestLeaseRegistryUnnamedHostnameContract(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "")
	_, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: identity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	expectedCanonical, err := utils.CanonicalLeaseHostname("", identity.Address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname error = %v", err)
	}
	if resp.Hostname != "" {
		t.Fatalf("RegisterResponse hostname = %q, want empty friendly hostname for unnamed service", resp.Hostname)
	}
	if resp.CanonicalHostname != expectedCanonical {
		t.Fatalf("RegisterResponse canonical hostname = %q, want %q", resp.CanonicalHostname, expectedCanonical)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || leases[0].Hostname != "" || leases[0].CanonicalHostname != expectedCanonical || leases[0].Address != identity.Address {
		t.Fatalf("PublicLeases() = %+v, want the registered unnamed lease", leases)
	}
	if _, ok := registry.Lookup(expectedCanonical); !ok {
		t.Fatal("Lookup(canonical hostname) = false, want registered unnamed lease")
	}
}

func TestLeaseRegistryUnnamedReplacementAndNamedCoexistence(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	unnamedIdentity := newTestLeaseIdentity(t, "")
	_, firstUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: unnamedIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("first unnamed Register() error = %v", err)
	}

	// Re-registering the same unnamed identity replaces the previous one.
	secondUnnamedRecord, secondUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: unnamedIdentity,
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("second unnamed Register() error = %v", err)
	}
	if firstUnnamedResp.CanonicalHostname != secondUnnamedResp.CanonicalHostname {
		t.Fatalf("canonical hostname changed across replacement: first=%q second=%q", firstUnnamedResp.CanonicalHostname, secondUnnamedResp.CanonicalHostname)
	}
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after unnamed replacement", len(leases))
	}

	// Registering a named service under the same address creates a distinct identity that coexists.
	namedIdentity := unnamedIdentity
	namedIdentity.Name = "myapp"
	_, namedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: namedIdentity,
	}, netip.MustParseAddr("203.0.113.12"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("named Register() error = %v", err)
	}
	if namedResp.CanonicalHostname == secondUnnamedResp.CanonicalHostname {
		t.Fatalf("named and unnamed services got the same canonical hostname %q", namedResp.CanonicalHostname)
	}

	leases := registry.PublicLeases(time.Now())
	if len(leases) != 2 {
		t.Fatalf("PublicLeases() length = %d, want 2 for distinct named and unnamed services", len(leases))
	}
	unnamedLookup, ok := registry.Lookup(secondUnnamedResp.CanonicalHostname)
	if !ok || unnamedLookup != secondUnnamedRecord {
		t.Fatalf("Lookup(unnamed) = (%+v, %v), want secondUnnamedRecord", unnamedLookup, ok)
	}
	namedLookup, ok := registry.Lookup(namedResp.CanonicalHostname)
	if !ok || namedLookup.Name != "myapp" {
		t.Fatalf("Lookup(named) = (%+v, %v), want myapp lease", namedLookup, ok)
	}
}

func TestLeaseTokensAreBoundToLeaseInstance(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "replace")
	_, firstResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	second, secondResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("second Register() error = %v", err)
	}
	if firstResponse.CanonicalHostname != secondResponse.CanonicalHostname {
		t.Fatalf("canonical hostname changed across reconnect: first=%q second=%q", firstResponse.CanonicalHostname, secondResponse.CanonicalHostname)
	}
	if _, err := registry.admitReverseCapability(firstResponse.ReverseEndpoint.Capability); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old reverse capability error = %v, want unauthorized", err)
	}
	if _, err := registry.admitLeaseByToken(firstResponse.AccessToken, false); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token admission error = %v, want unauthorized", err)
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: firstResponse.AccessToken}, netip.MustParseAddr("203.0.113.12"), nil); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token renew error = %v, want unauthorized", err)
	}
	if _, err := registry.resolveReverseEndpoint(types.ReverseEndpointRequest{AccessToken: firstResponse.AccessToken}); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token reverse refresh error = %v, want unauthorized", err)
	}
	if _, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, firstResponse.AccessToken)); ok {
		t.Fatal("verifySigningAccessTokenLease() old access token = true, want false")
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: firstResponse.AccessToken}); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token unregister error = %v, want unauthorized", err)
	}
	if second.sourceAddr != netip.MustParseAddr("203.0.113.11") {
		t.Fatalf("replacement lease source = %v after old token operations, want unchanged", second.sourceAddr)
	}
	if _, ok := registry.Lookup("replace.example.com"); !ok {
		t.Fatal("Lookup() after replacement = false, want active replacement lease")
	}
	if _, err := registry.admitReverseCapability(secondResponse.ReverseEndpoint.Capability); err != nil {
		t.Fatalf("new reverse capability admission error = %v, want admitted", err)
	}
	if _, err := registry.admitLeaseByToken(secondResponse.AccessToken, false); err != nil {
		t.Fatalf("new access token admission error = %v, want admitted", err)
	}
	if leaseID, ok := registry.verifySigningAccessTokenLease(signLeaseRequest(t, secondResponse.AccessToken)); !ok || leaseID == "" {
		t.Fatalf("verifySigningAccessTokenLease() new access token = (%q, %v), want live lease", leaseID, ok)
	}
}

func TestLeaseRegistryLegacyClientRejectsHostnameConflict(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	_, first, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(free legacy hostname) error = %v", err)
	}
	if first.Hostname != "conflict.example.com" {
		t.Fatalf("legacy friendly hostname = %q, want conflict.example.com", first.Hostname)
	}
	_, _, err = registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if !errors.Is(err, errHostnameConflict) {
		t.Fatalf("Register(conflicting legacy hostname) error = %v, want hostname conflict", err)
	}
}

func TestLeaseRegistryAllowsCanonicalFallbackForSameName(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	firstIdentity := newTestLeaseIdentity(t, "conflict")
	_, first, err := registry.Register(types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               firstIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(conflict first) error = %v", err)
	}
	secondIdentity := newTestLeaseIdentity(t, "conflict")
	_, second, err := registry.Register(types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               secondIdentity,
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(conflict second) error = %v", err)
	}
	if second.Hostname != "" {
		t.Fatalf("second friendly hostname = %q, want unavailable", second.Hostname)
	}
	if first.CanonicalHostname == second.CanonicalHostname {
		t.Fatalf("different owners received the same canonical hostname %q", first.CanonicalHostname)
	}
	for hostname, wantAddress := range map[string]string{
		first.CanonicalHostname:  firstIdentity.Address,
		second.CanonicalHostname: secondIdentity.Address,
	} {
		record, ok := registry.Lookup(hostname)
		if !ok || record.Address != wantAddress {
			t.Fatalf("Lookup(%q) = (%+v, %v), want address %q", hostname, record, ok, wantAddress)
		}
	}

	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatalf("Unregister(first) error = %v", err)
	}
	_, secondReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: secondIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(second reconnect) error = %v", err)
	}
	if secondReconnect.Hostname != "conflict.example.com" || secondReconnect.CanonicalHostname != second.CanonicalHostname {
		t.Fatalf("second reconnect hostnames = (%q, %q), want friendly reuse with stable canonical %q", secondReconnect.Hostname, secondReconnect.CanonicalHostname, second.CanonicalHostname)
	}
	_, firstReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(first reconnect) error = %v", err)
	}
	if firstReconnect.Hostname != "" || firstReconnect.CanonicalHostname != first.CanonicalHostname {
		t.Fatalf("first reconnect hostnames = (%q, %q), want unavailable friendly name and stable canonical %q", firstReconnect.Hostname, firstReconnect.CanonicalHostname, first.CanonicalHostname)
	}
}

func TestLeaseRegistryPolicyViewsUsePushedAccess(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "demo")
	registry.setIdentityRoutable(identity.ServiceKey(), false, 1)
	record, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: identity,
	}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	identityKey := record.ServiceKey()

	// The relay pushes the fail-closed result before registration so a new
	// lease cannot appear in public state before its access decision.
	if leases := registry.PublicLeases(time.Now()); len(leases) != 0 {
		t.Fatalf("PublicLeases() length = %d, want 0 while not routable", len(leases))
	}
	if _, err := registry.admitLeaseByToken(resp.AccessToken, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("admitLeaseByToken() error = %v, want lease rejected while not routable", err)
	}

	registry.setIdentityRoutable(identityKey, true, 2)
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after the relay routes the identity", len(leases))
	}
	if _, err := registry.admitLeaseByToken(resp.AccessToken, false); err != nil {
		t.Fatalf("admitLeaseByToken() error = %v, want admitted once routable", err)
	}
}

func TestAccessRevisionRejectsInFlightAllow(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "revision")
	_, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := leaseIdentity.ServiceKey()
	registry.setIdentityRoutable(key, true, 1)
	loaded := make(chan struct{})
	resume := make(chan struct{})
	applied := make(chan bool, 1)
	go func() {
		// An old registration has already read revision 1's allow but has
		// not delivered it. Force it to arrive after the denial completes.
		close(loaded)
		<-resume
		applied <- registry.setIdentityRoutable(key, true, 1)
	}()
	<-loaded
	registry.setIdentityRoutable(key, false, 2)
	close(resume)
	if <-applied {
		t.Fatal("stale allow was applied after the newer denial")
	}
	if _, err := registry.admitLeaseByToken(lease.AccessToken, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("delayed allow bypassed denial: %v", err)
	}
	registry.setIdentityRoutable(key, true, 3)
	if _, err := registry.admitLeaseByToken(lease.AccessToken, false); err != nil {
		t.Fatalf("newer allow failed to restore access: %v", err)
	}
}

func TestAccessRevisionSurvivesIdleCleanupAndRegistration(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	key := types.NewServiceIdentityKey("revision", "identity")
	registry.setIdentityRoutable(key, false, 2)
	registry.cleanupExpired(time.Now().Add(defaultRegisterChallengeTTL + time.Second))
	if registry.setIdentityRoutable(key, true, 1) {
		t.Fatal("idle cleanup forgot the revision fence")
	}
	registry.setIdentityRoutable(key, true, 3)
	registry.suspendIdentity(key)
	if registry.isRoutable(key) {
		t.Fatal("registration was not fail-closed")
	}
	if registry.setIdentityRoutable(key, true, 2) {
		t.Fatal("registration accepted an older revision")
	}
	if !registry.setIdentityRoutable(key, true, 3) || !registry.isRoutable(key) {
		t.Fatal("current committed revision did not release registration")
	}
}

func TestLeaseRegistryCleanupExpiredPreservesIdentityBPS(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "expired"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registry.bps.SetIdentityBPS(record.ServiceKey(), 1024)

	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	registry.cleanupExpired(time.Now())

	if _, ok := registry.Lookup("expired.example.com"); ok {
		t.Fatal("Lookup() after cleanupExpired() = true, want false")
	}
	if bps := registry.bps.IdentityBPS(record.ServiceKey()); bps != 1024 {
		t.Fatalf("IdentityBPS() after cleanupExpired() = %d, want configured limit preserved", bps)
	}
}

func TestIssueRegisterChallengeBoundsPending(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		limit int
	}{
		{"per IP", defaultRegisterChallengeOutstandingPerIP},
		{"global", defaultRegisterChallengeOutstanding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, false, false)
			sourceAddr := netip.MustParseAddr("203.0.113.50")
			request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "pending")}
			for i := range tc.limit {
				if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr); err != nil {
					t.Fatalf("issueRegisterChallenge(%d) error = %v", i, err)
				}
				if tc.name == "global" {
					sourceAddr = sourceAddr.Next()
				}
			}
			if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr); !errors.Is(err, errRegisterChallengePending) {
				t.Fatalf("issueRegisterChallenge() error = %v, want pending limit", err)
			}
			if len(registry.records) != tc.limit {
				t.Fatal("rejected challenge was retained")
			}
			expiredAt := time.Now().Add(-time.Second)
			registry.mu.Lock()
			for _, record := range registry.records {
				record.ExpiresAt = expiredAt
				record.registerChallenge.ExpiresAt = expiredAt
			}
			registry.mu.Unlock()
			if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr); err != nil {
				t.Fatalf("issueRegisterChallenge() after expired cleanup error = %v", err)
			}
			if len(registry.records) != 1 {
				t.Fatal("expired challenges were retained")
			}
		})
	}
}

func TestIssueRegisterChallengeAcceptsLongName(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if _, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "twenty-three-charactersx"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, netip.MustParseAddr("203.0.113.50")); err != nil {
		t.Fatalf("issueRegisterChallenge(long name) error = %v", err)
	}
}

func TestMissingLeaseRecordReportsLeaseNotFound(t *testing.T) {
	t.Parallel()

	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	newRegistry := func() *leaseRegistry {
		t.Helper()
		registry, registryErr := newLeaseRegistry(0, 0, relay.Name, relayAuthority, "https://example.com")
		if registryErr != nil {
			t.Fatalf("newLeaseRegistry() error = %v", registryErr)
		}
		return registry
	}
	// The same relay identity in a fresh registry simulates a relay restart:
	// tokens stay verifiable while the in-memory lease records are gone.
	before, restarted := newRegistry(), newRegistry()

	_, resp, err := before.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "restart")}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.AccessToken == "" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("register response missing credentials: %+v", resp)
	}

	if _, err := restarted.admitLeaseByToken(resp.AccessToken, false); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("admitLeaseByToken() after restart = %v, want lease not found", err)
	}
	if _, err := restarted.admitReverseCapability(resp.ReverseEndpoint.Capability); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("admitReverseCapability() after restart = %v, want lease not found", err)
	}
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: resp.AccessToken}, netip.MustParseAddr("203.0.113.10"), nil); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("Renew() after restart = %v, want lease not found", err)
	}
	if _, err := restarted.resolveReverseEndpoint(types.ReverseEndpointRequest{AccessToken: resp.AccessToken}); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("RefreshReverseEndpoint() after restart = %v, want lease not found", err)
	}
	if _, ok := restarted.verifySigningAccessTokenLease(signLeaseRequest(t, resp.AccessToken)); ok {
		t.Fatal("verifySigningAccessTokenLease() after restart = true, want false for missing lease")
	}

	if _, err := restarted.admitReverseCapability("forged"); !errors.Is(err, errUnauthorized) {
		t.Fatalf("admitReverseCapability() forged = %v, want unauthorized", err)
	}
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: "forged"}, netip.MustParseAddr("203.0.113.10"), nil); !errors.Is(err, errUnauthorized) {
		t.Fatalf("Renew() forged = %v, want unauthorized", err)
	}
}

func TestPortPoolRollbackReturnsPortWithoutReservation(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "first", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "other", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.rollback(port, first)
	if len(pool.reserved) != 0 {
		t.Fatalf("rollback created %d sticky reservations", len(pool.reserved))
	}
	reused, err := pool.allocate(other)
	if err != nil || reused != port {
		t.Fatalf("different owner did not immediately reuse rolled-back port: %d, %v", reused, err)
	}
	pool.rollback(port, first)
	if pool.inUse[port].record != other {
		t.Fatal("stale rollback released another owner's port")
	}
}

func TestLeaseHostnameConflictRollsBackRawPorts(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	request := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "conflict"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		request.Identity = newTestLeaseIdentity(t, "conflict")
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errHostnameConflict) {
			t.Fatalf("rejected registration %d error = %v, want hostname conflict", i, err)
		}
		if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
			len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
			t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
		}
	}
	request.Identity = newTestLeaseIdentity(t, "accepted")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("rejected identities exhausted raw ports: %v", err)
	}
}

func TestPortPoolRollbackPreservesReconnectReservation(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "first", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "other", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	original := pool.reserved[first.ServiceKey()]
	if reclaimed, err := pool.allocate(first); err != nil || reclaimed != port {
		t.Fatalf("reclaim = %d, %v", reclaimed, err)
	}
	pool.rollback(port, first)
	if restored := pool.reserved[first.ServiceKey()]; restored != original {
		t.Fatalf("reservation changed after rejected reconnect: got %+v, want %+v", restored, original)
	}
	if _, err := pool.allocate(other); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another identity consumed the reconnect reservation: %v", err)
	}
	pool.cleanupExpired(original.expiresAt.Add(time.Nanosecond))
	if reused, err := pool.allocate(other); err != nil || reused != port {
		t.Fatalf("expired reservation was not returned: %d, %v", reused, err)
	}
}

func TestLeaseCapacityRejectionRollsBackRawPorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limitUDP  bool
		wantError error
	}{
		{name: "UDP", limitUDP: true, wantError: errUDPCapacityExceeded},
		{name: "TCP", wantError: errTCPPortCapacityExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := newTestRegistry(t, true, true)
			request := types.RegisterChallengeRequest{
				Identity:   newTestLeaseIdentity(t, "owner"),
				UDPEnabled: true,
				TCPEnabled: true,
			}
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if tc.limitUDP {
				registry.setUDPPolicy(true, 1)
			} else {
				registry.setTCPPortPolicy(true, 1)
			}
			for i := range 3 {
				request.Identity = newTestLeaseIdentity(t, fmt.Sprintf("rejected-%d", i))
				if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, tc.wantError) {
					t.Fatalf("rejected registration %d error = %v, want %v", i, err, tc.wantError)
				}
				if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
					len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
					t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
				}
			}
			registry.setUDPPolicy(true, 2)
			registry.setTCPPortPolicy(true, 2)
			request.Identity = newTestLeaseIdentity(t, "accepted")
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatalf("capacity rejection exhausted raw ports: %v", err)
			}
		})
	}
}

func TestLeaseTCPPortExhaustionRollsBackAllocatedUDPPort(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	for i := range 2 {
		request := types.RegisterChallengeRequest{
			Identity:   newTestLeaseIdentity(t, fmt.Sprintf("tcp-%d", i)),
			TCPEnabled: true,
		}
		if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	both := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "both"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	if _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("Register() error = %v, want TCP port exhaustion", err)
	}
	if len(registry.udpPorts.available) != 2 || len(registry.udpPorts.reserved) != 0 {
		t.Fatalf("failed TCP allocation retained a UDP port: %+v", registry.udpPorts)
	}
	both.TCPEnabled = false
	both.Identity = newTestLeaseIdentity(t, "udp")
	if _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("failed TCP allocation exhausted UDP ports: %v", err)
	}
}

func TestPortPoolReservesReleasedPortForOwner(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, time.Minute)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if _, err := pool.allocate(other); !errors.Is(err, errPortExhausted) {
		t.Fatalf("another owner consumed reserved port: %v", err)
	}
	if reclaimed, err := pool.allocate(first); err != nil || reclaimed != port {
		t.Fatalf("owner reclaim = %d, %v", reclaimed, err)
	}
}

func TestPortPoolReusesPortAfterReservationExpires(t *testing.T) {
	first := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x1"}}
	other := &leaseRecord{Identity: types.Identity{Name: "demo", Address: "0x2"}}
	pool := newPortPool(10000, 10000, -time.Second)
	port, err := pool.allocate(first)
	if err != nil {
		t.Fatal(err)
	}
	pool.release(port, first)
	if reused, err := pool.allocate(other); err != nil || reused != port {
		t.Fatalf("expired reservation = %d, %v", reused, err)
	}
}

func TestLeasePortsStayWithServiceIdentityAcrossReconnect(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	firstIdentity := newTestLeaseIdentity(t, "shared")
	request := types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity, UDPEnabled: true, TCPEnabled: true}
	firstRecord, first, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatal(err)
	}
	request.Identity = newTestLeaseIdentity(t, "shared")
	_, other, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, firstUDP, _ := net.SplitHostPort(first.UDPAddr)
	_, firstTCP, _ := net.SplitHostPort(first.TCPAddr)
	_, otherUDP, _ := net.SplitHostPort(other.UDPAddr)
	_, otherTCP, _ := net.SplitHostPort(other.TCPAddr)
	if firstUDP == otherUDP || firstTCP == otherTCP {
		t.Fatalf("same-name identity inherited a sticky port: first=%s/%s, other=%s/%s", firstUDP, firstTCP, otherUDP, otherTCP)
	}
	request.Identity = firstIdentity
	_, reconnected, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.UDPAddr != first.UDPAddr || reconnected.TCPAddr != first.TCPAddr {
		t.Fatalf("reconnect lost reserved addresses: got %s/%s, want %s/%s", reconnected.UDPAddr, reconnected.TCPAddr, first.UDPAddr, first.TCPAddr)
	}
	registry.closeRecord(firstRecord)
	request.Identity = newTestLeaseIdentity(t, "third")
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errUDPPortExhausted) {
		t.Fatalf("stale cleanup released a live UDP port: %v", err)
	}
	request.UDPEnabled = false
	if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("stale cleanup released a live TCP port: %v", err)
	}
}

func TestLeaseRegistrationFailureReleasesPorts(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			registry := newTestRegistry(t, true, true)
			request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "retry"), UDPEnabled: true, TCPEnabled: true}
			port := registry.tcpPorts.available[0]
			var occupied io.Closer
			var err error
			if network == "tcp" {
				occupied, err = net.ListenTCP("tcp", &net.TCPAddr{Port: port})
			} else {
				occupied, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err == nil {
				t.Fatal("registration succeeded with an occupied port")
			}
			if len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
				t.Fatal("socket start failure created sticky port reservations")
			}
			request.Identity = newTestLeaseIdentity(t, "different")
			if _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatalf("occupied port prevented another identity using free ports: %v", err)
			}
			_ = occupied.Close()
			request.Identity = newTestLeaseIdentity(t, "recovered")
			_, response, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
			if err != nil {
				t.Fatalf("registration could not reuse ports after the socket was closed: %v", err)
			}
			_, actual, _ := net.SplitHostPort(response.TCPAddr)
			if actual != fmt.Sprint(port) {
				t.Fatalf("registration leaked its TCP port: got %s, want %d", actual, port)
			}
			_, actual, _ = net.SplitHostPort(response.UDPAddr)
			if actual != fmt.Sprint(port) {
				t.Fatalf("registration leaked its UDP port: got %s, want %d", actual, port)
			}
		})
	}
}

func TestLeaseBridgeCapacityAndRevocation(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "lease", Address: "0x1"}, ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}, blocked: make(map[types.ServiceIdentityKey]time.Time)}
	var bridges []*leaseBridge
	for index := range defaultLeaseBridgeLimit {
		inbound, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		bridge, err := registry.admitBridge(t.Context(), record, inbound)
		if err != nil {
			t.Fatal(err)
		}
		if index < 16 {
			reverse, other := net.Pipe()
			t.Cleanup(func() { _ = other.Close() })
			if err := registry.activateBridge(record, bridge, reverse); err != nil {
				t.Fatal(err)
			}
		}
		bridges = append(bridges, bridge)
		defer record.releaseBridge(bridge)
	}
	excess, peer := net.Pipe()
	defer excess.Close()
	defer peer.Close()
	if _, err := registry.admitBridge(t.Context(), record, excess); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("capacity admission = %v", err)
	}
	registry.setIdentityRoutable(record.ServiceKey(), false, 1)
	registry.setIdentityRoutable(record.ServiceKey(), true, 2)
	for _, bridge := range bridges {
		if !errors.Is(bridge.ctx.Err(), context.Canceled) {
			t.Fatal("deny did not cancel bridge")
		}
		reverse, peer := net.Pipe()
		err := registry.activateBridge(record, bridge, reverse)
		_ = reverse.Close()
		_ = peer.Close()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("allow revived old reservation: %v", err)
		}
	}
	if _, err := registry.admitBridge(t.Context(), record, excess); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("revoked workers prematurely released capacity: %v", err)
	}
	record.releaseBridge(bridges[0])
	fresh, err := registry.admitBridge(t.Context(), record, excess)
	if err != nil {
		t.Fatalf("capacity not recovered: %v", err)
	}
	record.releaseBridge(fresh)
}

func TestLeaseBridgeRejectsExpiredAdmissionAfterWait(t *testing.T) {
	record := &leaseRecord{ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}}
	inbound, peer := net.Pipe()
	defer peer.Close()
	bridge, err := registry.admitBridge(t.Context(), record, inbound)
	if err != nil {
		t.Fatal(err)
	}
	defer record.releaseBridge(bridge)
	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	reverse, other := net.Pipe()
	defer reverse.Close()
	defer other.Close()
	if err := registry.activateBridge(record, bridge, reverse); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("expired activation=%v", err)
	}
}

func TestLeaseConcurrentRenewAndBridgeAdmission(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	record, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "renew-bridge")}, netip.MustParseAddr("127.0.0.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			if _, _, err := registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: 120}, netip.Addr{}, nil); err != nil {
				t.Error(err)
				return
			}
		}
	})
	workers.Go(func() {
		for range 100 {
			inbound, peer := net.Pipe()
			bridge, err := registry.admitBridge(t.Context(), record, inbound)
			if err != nil {
				_ = inbound.Close()
				_ = peer.Close()
				t.Error(err)
				return
			}
			reverse, other := net.Pipe()
			if err := registry.activateBridge(record, bridge, reverse); err != nil {
				t.Error(err)
			}
			record.releaseBridge(bridge)
			_ = peer.Close()
			_ = other.Close()
		}
	})
	workers.Wait()
}

// An SDK that pins the relay chain once (one that does not set RepinsChain)
// trusts its /v1/sign connection to that chain only. When the relay serves a
// certificate that chain does not verify, renewing the lease would only keep a
// tenant alive that fails every handshake, so the relay answers lease_not_found
// and the SDK registers again; nothing else is ever asked to.
func TestRenewAsksOnlyLeasesLeftBehindByTheRelayCertificateToRegisterAgain(t *testing.T) {
	t.Parallel()

	intermediate, otherIntermediate := newTestRelayIntermediate(t, "R10"), newTestRelayIntermediate(t, "R11")
	pinned := intermediate.issue(t, "example.com")
	sameIntermediate := intermediate.issue(t, "example.com")
	otherIssuer := otherIntermediate.issue(t, "example.com")
	for _, test := range []struct {
		name        string
		repins      bool
		registered  *acme.TLSMaterial
		current     *acme.TLSMaterial
		wantRenewed bool
	}{
		{"an SDK that re-pins by itself", true, pinned, otherIssuer, true},
		{"the certificate it registered under", false, pinned, pinned, true},
		{"a renewal by the same intermediate", false, pinned, sameIntermediate, true},
		{"a renewal by another intermediate", false, pinned, otherIssuer, false},
		{"a lease registered before the relay knew its certificate", false, nil, otherIssuer, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registry := newTestRegistry(t, false, false)
			tenant := newTestLeaseIdentity(t, "tenant")
			_, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: tenant}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, test.registered)
			if err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			_, _, err = registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: 600, RepinsChain: test.repins}, netip.MustParseAddr("203.0.113.10"), test.current)
			record, ok := registry.Lookup(registered.CanonicalHostname)
			if !ok {
				t.Fatal("Lookup() found no lease after Renew()")
			}
			if test.wantRenewed {
				if err != nil || !record.ExpiresAt.After(registered.ExpiresAt) {
					t.Fatalf("Renew() = %v, expiry %v; want the lease renewed past %v", err, record.ExpiresAt, registered.ExpiresAt)
				}
				return
			}
			if !errors.Is(err, errLeaseNotFound) || !record.ExpiresAt.Equal(registered.ExpiresAt) {
				t.Fatalf("Renew() = %v, expiry %v; want lease_not_found and the lease left to expire at %v", err, record.ExpiresAt, registered.ExpiresAt)
			}
			// Registering again records the certificate served now, so the same
			// change does not ask this lease a second time.
			_, again, err := registry.Register(types.RegisterChallengeRequest{Identity: tenant}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, test.current)
			if err != nil {
				t.Fatalf("Register() again error = %v", err)
			}
			if _, _, err := registry.Renew(types.RenewRequest{AccessToken: again.AccessToken, TTL: 600}, netip.MustParseAddr("203.0.113.10"), test.current); err != nil {
				t.Fatalf("Renew() after registering again = %v, want the lease renewed", err)
			}
		})
	}
}

type testRelayIntermediate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestRelayIntermediate(t *testing.T, name string) testRelayIntermediate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testRelayIntermediate{cert: cert, key: key}
}

// issue returns relay material for host, served as the leaf followed by this
// intermediate, as an ACME bundle is.
func (i testRelayIntermediate) issue(t *testing.T, host string) *acme.TLSMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, "*." + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw})...)
	certificate, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &acme.TLSMaterial{CertPEM: certPEM, Certificate: certificate}
}
