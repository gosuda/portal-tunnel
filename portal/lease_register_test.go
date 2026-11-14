package portal

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestRegisterOverlayPreferenceFallsBackToDirect(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, _, registered, err := registry.Register(types.RegisterChallengeRequest{
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
	resp := registerLeaseRegistryLifecycleDemo(t, registry)
	checkLifecycleRegistration(t, registry, resp)
	renewed, endpointInput := renewLifecycleLease(t, registry, resp)
	rotateLifecycleCapability(t, registry, endpointInput, resp)
	unregisterLifecycleLease(t, registry, renewed.AccessToken)
}

func registerLeaseRegistryLifecycleDemo(t *testing.T, registry *leaseRegistry) types.RegisterResponse {
	t.Helper()
	_, _, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "demo"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.ReverseEndpoint.URL != "https://example.com/sdk/connect" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("Register() reverse endpoint = %#v, want direct capability", resp.ReverseEndpoint)
	}
	return resp
}

func checkLifecycleRegistration(t *testing.T, registry *leaseRegistry, resp types.RegisterResponse) {
	t.Helper()
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
}

func renewLifecycleLease(t *testing.T, registry *leaseRegistry, resp types.RegisterResponse) (types.RenewResponse, reverseEndpointInput) {
	t.Helper()
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
	return renewed, endpointInput
}

func rotateLifecycleCapability(t *testing.T, registry *leaseRegistry, endpointInput reverseEndpointInput, resp types.RegisterResponse) {
	t.Helper()
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
}

func unregisterLifecycleLease(t *testing.T, registry *leaseRegistry, accessToken string) {
	t.Helper()
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: accessToken}); err != nil {
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
			checkLeaseRegistryTTLBoundsCase(t, seconds)
		})
	}
}

func checkLeaseRegistryTTLBoundsCase(t *testing.T, seconds int) {
	t.Helper()
	registry := newTestRegistry(t, false, false)
	request := types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "ttl"), TTL: seconds}
	_, challengeErr := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, netip.Addr{})
	started := time.Now().UTC().Truncate(time.Second)
	_, _, response, registerErr := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if seconds > 600 {
		rejectOversizeTTL(t, registry, challengeErr, registerErr)
		return
	}
	if challengeErr != nil || registerErr != nil {
		t.Fatalf("accepted TTL: challenge error=%v, registration error=%v", challengeErr, registerErr)
	}
	verifyLeaseRegistryTTLBoundsExpiry(t, seconds, started, response)
}

func rejectOversizeTTL(t *testing.T, registry *leaseRegistry, challengeErr error, registerErr error) {
	t.Helper()
	if !errors.Is(challengeErr, errLeaseTTLExceeded) || !errors.Is(registerErr, errLeaseTTLExceeded) {
		t.Fatalf("oversized TTL: challenge error=%v, registration error=%v", challengeErr, registerErr)
	}
	if len(registry.records) != 0 {
		t.Fatal("rejected TTL retained a challenge or lease")
	}
}

func verifyLeaseRegistryTTLBoundsExpiry(t *testing.T, seconds int, started time.Time, response types.RegisterResponse) {
	t.Helper()
	ttl := 120 * time.Second
	if seconds > 0 {
		ttl = time.Duration(seconds) * time.Second
	}
	if response.ExpiresAt.Before(started.Add(ttl)) || response.ExpiresAt.After(time.Now().Add(ttl)) {
		t.Fatalf("lease expiry=%v, want TTL %v", response.ExpiresAt, ttl)
	}
}

func TestLeaseRegistryInvalidRenewPreservesLease(t *testing.T) {
	t.Parallel()
	registry := newTestRegistry(t, false, false)
	fixture := seedInvalidRenewFixture(t, registry)
	for _, request := range []types.RenewRequest{
		{TTL: 600, Metadata: types.LeaseMetadata{Description: strings.Repeat("a", 4097)}},
		{TTL: 601},
		{TTL: math.MaxInt},
	} {
		rejectInvalidRenew(t, registry, fixture, request)
	}
}

type leaseRegistryInvalidRenewFixture struct {
	record         *leaseRecord
	response       types.RegisterResponse
	before         types.Lease
	beforeSource   netip.Addr
	beforeReported string
}

func seedInvalidRenewFixture(t *testing.T, registry *leaseRegistry) leaseRegistryInvalidRenewFixture {
	t.Helper()
	record, _, registered, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "invalid-renew"),
		TTL:      60,
		Metadata: types.LeaseMetadata{Description: "original", Tags: []string{"original"}},
	}, netip.MustParseAddr("203.0.113.10"), "198.51.100.10", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return leaseRegistryInvalidRenewFixture{
		record:         record,
		response:       registered,
		before:         registry.publicLease(record, time.Now()),
		beforeSource:   record.sourceAddr,
		beforeReported: record.ReportedIP,
	}
}

func rejectInvalidRenew(t *testing.T, registry *leaseRegistry, fixture leaseRegistryInvalidRenewFixture, request types.RenewRequest) {
	t.Helper()
	request.AccessToken = fixture.response.AccessToken
	request.ReportedIP = "198.51.100.11"
	if _, _, err := registry.Renew(request, netip.MustParseAddr("203.0.113.11"), nil); err == nil {
		t.Fatal("Renew() accepted invalid metadata or TTL")
	}
	if after := registry.publicLease(fixture.record, time.Now()); !reflect.DeepEqual(after, fixture.before) {
		t.Fatalf("rejected Renew() changed lease: before=%+v after=%+v", fixture.before, after)
	}
	if fixture.record.sourceAddr != fixture.beforeSource || fixture.record.ReportedIP != fixture.beforeReported {
		t.Fatal("rejected Renew() changed source or reported IP")
	}
}

func TestLeaseRegistryUnnamedHostnameContract(t *testing.T) {
	t.Parallel()
	registry := newTestRegistry(t, false, false)
	leasedIdentity, resp := registerUnnamedLease(t, registry)
	expectedCanonical := checkUnnamedHostnames(t, leasedIdentity, resp)
	checkUnnamedListing(t, registry, leasedIdentity, expectedCanonical)
}

func registerUnnamedLease(t *testing.T, registry *leaseRegistry) (types.Identity, types.RegisterResponse) {
	t.Helper()
	leasedIdentity := newTestLeaseIdentity(t, "")
	_, _, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: leasedIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return leasedIdentity, resp
}

func checkUnnamedHostnames(t *testing.T, leasedIdentity types.Identity, resp types.RegisterResponse) string {
	t.Helper()
	expectedCanonical, err := utils.CanonicalLeaseHostname("", leasedIdentity.Address, "example.com")
	if err != nil {
		t.Fatalf("CanonicalLeaseHostname error = %v", err)
	}
	if resp.Hostname != "" {
		t.Fatalf("RegisterResponse hostname = %q, want empty friendly hostname for unnamed service", resp.Hostname)
	}
	if resp.CanonicalHostname != expectedCanonical {
		t.Fatalf("RegisterResponse canonical hostname = %q, want %q", resp.CanonicalHostname, expectedCanonical)
	}
	return expectedCanonical
}

func checkUnnamedListing(t *testing.T, registry *leaseRegistry, leasedIdentity types.Identity, expectedCanonical string) {
	t.Helper()
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || leases[0].Hostname != "" || leases[0].CanonicalHostname != expectedCanonical || leases[0].Address != leasedIdentity.Address {
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
	secondRecord, secondResp := replaceUnnamedLease(t, registry, unnamedIdentity)
	checkNamedCoexistence(t, registry, unnamedIdentity, secondRecord, secondResp)
}

func replaceUnnamedLease(t *testing.T, registry *leaseRegistry, unnamedIdentity types.Identity) (*leaseRecord, types.RegisterResponse) {
	t.Helper()
	_, _, firstUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: unnamedIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("first unnamed Register() error = %v", err)
	}
	secondUnnamedRecord, _, secondUnnamedResp, err := registry.Register(types.RegisterChallengeRequest{
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
	return secondUnnamedRecord, secondUnnamedResp
}

func checkNamedCoexistence(t *testing.T, registry *leaseRegistry, unnamedIdentity types.Identity, secondRecord *leaseRecord, secondResp types.RegisterResponse) {
	t.Helper()
	namedIdentity := unnamedIdentity
	namedIdentity.Name = "myapp"
	_, _, namedResp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: namedIdentity,
	}, netip.MustParseAddr("203.0.113.12"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("named Register() error = %v", err)
	}
	if namedResp.CanonicalHostname == secondResp.CanonicalHostname {
		t.Fatalf("named and unnamed services got the same canonical hostname %q", namedResp.CanonicalHostname)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 2 {
		t.Fatalf("PublicLeases() length = %d, want 2 for distinct named and unnamed services", len(leases))
	}
	unnamedLookup, ok := registry.Lookup(secondResp.CanonicalHostname)
	if !ok || unnamedLookup != secondRecord {
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
	firstResponse, secondResponse, second := registerInstancePair(t, registry, leaseIdentity)
	rejectStaleInstanceTokens(t, registry, firstResponse, second)
	admitCurrentInstanceTokens(t, registry, secondResponse)
}

func registerInstancePair(t *testing.T, registry *leaseRegistry, leaseIdentity types.Identity) (types.RegisterResponse, types.RegisterResponse, *leaseRecord) {
	t.Helper()
	_, _, firstResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	second, _, secondResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("second Register() error = %v", err)
	}
	if firstResponse.CanonicalHostname != secondResponse.CanonicalHostname {
		t.Fatalf("canonical hostname changed across reconnect: first=%q second=%q", firstResponse.CanonicalHostname, secondResponse.CanonicalHostname)
	}
	return firstResponse, secondResponse, second
}

func rejectStaleInstanceTokens(t *testing.T, registry *leaseRegistry, firstResponse types.RegisterResponse, second *leaseRecord) {
	t.Helper()
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
}

func admitCurrentInstanceTokens(t *testing.T, registry *leaseRegistry, secondResponse types.RegisterResponse) {
	t.Helper()
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
	_, _, first, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(free legacy hostname) error = %v", err)
	}
	if first.Hostname != "conflict.example.com" {
		t.Fatalf("legacy friendly hostname = %q, want conflict.example.com", first.Hostname)
	}
	_, _, _, err = registry.Register(types.RegisterChallengeRequest{
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
	secondIdentity := newTestLeaseIdentity(t, "conflict")
	first, second := registerCanonicalFallbackPair(t, registry, firstIdentity, secondIdentity)
	reconnectSecondFallbackLease(t, registry, secondIdentity, first.AccessToken, second)
	reconnectFirstFallbackLease(t, registry, firstIdentity, first)
}

func registerCanonicalFallbackPair(t *testing.T, registry *leaseRegistry, firstIdentity types.Identity, secondIdentity types.Identity) (types.RegisterResponse, types.RegisterResponse) {
	t.Helper()
	_, _, first, err := registry.Register(types.RegisterChallengeRequest{
		AllowCanonicalFallback: true,
		Identity:               firstIdentity,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(conflict first) error = %v", err)
	}
	_, _, second, err := registry.Register(types.RegisterChallengeRequest{
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
	return first, second
}

func reconnectSecondFallbackLease(t *testing.T, registry *leaseRegistry, secondIdentity types.Identity, firstAccessToken string, second types.RegisterResponse) {
	t.Helper()
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: firstAccessToken}); err != nil {
		t.Fatalf("Unregister(first) error = %v", err)
	}
	_, _, secondReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: secondIdentity}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(second reconnect) error = %v", err)
	}
	if secondReconnect.Hostname != "conflict.example.com" || secondReconnect.CanonicalHostname != second.CanonicalHostname {
		t.Fatalf("second reconnect hostnames = (%q, %q), want friendly reuse with stable canonical %q", secondReconnect.Hostname, secondReconnect.CanonicalHostname, second.CanonicalHostname)
	}
}

func reconnectFirstFallbackLease(t *testing.T, registry *leaseRegistry, firstIdentity types.Identity, first types.RegisterResponse) {
	t.Helper()
	_, _, firstReconnect, err := registry.Register(types.RegisterChallengeRequest{AllowCanonicalFallback: true, Identity: firstIdentity}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register(first reconnect) error = %v", err)
	}
	if firstReconnect.Hostname != "" || firstReconnect.CanonicalHostname != first.CanonicalHostname {
		t.Fatalf("first reconnect hostnames = (%q, %q), want unavailable friendly name and stable canonical %q", firstReconnect.Hostname, firstReconnect.CanonicalHostname, first.CanonicalHostname)
	}
}
