package portal

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
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
	relay, err := identity.LoadOrCreateRelayIdentity(filepath.Join(t.TempDir(), types.RelayIdentityFilename), "example.com")
	if err != nil {
		t.Fatalf("LoadOrCreateRelayIdentity() error = %v", err)
	}
	relayAuthority := identity.NewLocalAuthority(relay.Identity)
	registry, err := newLeaseRegistry(udpEnabled, tcpPortEnabled, 10000, 10100, relay.Name, 443, relayAuthority, "https://example.com", false, "")
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	// Registered leases bind UDP and raw-TCP relays; releasing them keeps
	// repeated runs in one process free of port collisions.
	t.Cleanup(func() { registry.CloseAll() })
	return registry
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
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
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
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.ReverseEndpoint.URL != "https://example.com/sdk/connect" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("Register() reverse endpoint = %#v, want direct capability", resp.ReverseEndpoint)
	}
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 || leases[0].Hostname != "demo.example.com" {
		t.Fatalf("PublicLeases() = %+v, want the registered demo lease", leases)
	}

	renewed, endpointInput, err := registry.Renew(types.RenewRequest{
		AccessToken: resp.AccessToken,
		TTL:         int((3 * time.Minute) / time.Second),
	}, "203.0.113.11")
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if !renewed.ExpiresAt.After(resp.ExpiresAt) {
		t.Fatalf("Renew() expires at = %v, want later than register expiry %v", renewed.ExpiresAt, resp.ExpiresAt)
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

func TestLeaseTokensAreBoundToLeaseInstance(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "replace")
	_, firstResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("first Register() error = %v", err)
	}
	second, secondResponse, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, "203.0.113.11", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("second Register() error = %v", err)
	}
	if _, err := registry.admitReverseCapability(firstResponse.ReverseEndpoint.Capability); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old reverse capability error = %v, want unauthorized", err)
	}
	if _, err := registry.admitLeaseByToken(firstResponse.AccessToken, false); !errors.Is(err, errUnauthorized) {
		t.Fatalf("old access token admission error = %v, want unauthorized", err)
	}
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: firstResponse.AccessToken}, "203.0.113.12"); !errors.Is(err, errUnauthorized) {
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
	if second.ClientIP != "203.0.113.11" {
		t.Fatalf("replacement lease client ip = %q after old token operations, want unchanged", second.ClientIP)
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

func TestLeaseRegistryHostnameConflict(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil); err != nil {
		t.Fatalf("Register(conflict first) error = %v", err)
	}
	_, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "conflict"),
	}, "203.0.113.11", "", types.RelayDescriptor{}, nil)
	if !errors.Is(err, errHostnameConflict) {
		t.Fatalf("Register(conflict second) error = %v, want hostname conflict", err)
	}
}

func TestLeaseRegistryPolicyViewsUseRoutablePolicy(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if err := registry.policy.Approver().SetMode(policy.ModeManual); err != nil {
		t.Fatalf("SetMode() error = %v", err)
	}
	if _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "demo"),
	}, "203.0.113.20", "", types.RelayDescriptor{}, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if leases := registry.PublicLeases(time.Now()); len(leases) != 0 {
		t.Fatalf("PublicLeases() length = %d, want 0 before approval", len(leases))
	}
	leases := registry.PolicyLeases(time.Now())
	if len(leases) != 1 {
		t.Fatalf("PolicyLeases() length = %d, want 1", len(leases))
	}
	if leases[0].IsApproved {
		t.Fatal("PolicyLeases()[0].IsApproved = true, want false before approval")
	}

	registry.policy.Approver().Approve(leases[0].IdentityKey)
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after approval", len(leases))
	}
	leases = registry.PolicyLeases(time.Now())
	if len(leases) != 1 || !leases[0].IsApproved {
		t.Fatalf("PolicyLeases() = %+v, want the approved lease", leases)
	}
}

func TestLeaseRegistryCleanupExpiredForgetsIdentity(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	record, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "expired"),
	}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registry.policy.BPSManager().SetIdentityBPS(record.Key(), 1024)

	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	registry.cleanupExpired(time.Now())

	if _, ok := registry.Lookup("expired.example.com"); ok {
		t.Fatal("Lookup() after cleanupExpired() = true, want false")
	}
	if bps := registry.policy.BPSManager().IdentityBPS(record.Key()); bps != 0 {
		t.Fatalf("IdentityBPS() after cleanupExpired() = %d, want identity forgotten", bps)
	}
}

func TestIssueRegisterChallengeBoundsPendingPerIP(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	clientIP := "203.0.113.50"
	for i := range defaultRegisterChallengeOutstandingPerIP {
		_, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
			Identity: newTestLeaseIdentity(t, fmt.Sprintf("demo-%d", i)),
		}, "example.com", "https://example.com"+types.PathSDKRegister, clientIP)
		if err != nil {
			t.Fatalf("issueRegisterChallenge(%d) error = %v", i, err)
		}
	}

	_, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "overflow"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, clientIP)
	if !errors.Is(err, errRegisterChallengePending) {
		t.Fatalf("issueRegisterChallenge() error = %v, want pending limit", err)
	}

	expiredAt := time.Now().Add(-time.Second)
	registry.mu.Lock()
	for _, record := range registry.records {
		if record == nil || record.registerChallenge == nil {
			continue
		}
		record.ExpiresAt = expiredAt
		record.registerChallenge.ExpiresAt = expiredAt
	}
	registry.mu.Unlock()

	_, err = registry.issueRegisterChallenge(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "after-cleanup"),
	}, "example.com", "https://example.com"+types.PathSDKRegister, clientIP)
	if err != nil {
		t.Fatalf("issueRegisterChallenge() after expired cleanup error = %v", err)
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
		registry, registryErr := newLeaseRegistry(false, false, 10000, 10100, relay.Name, 443, relayAuthority, "https://example.com", false, "")
		if registryErr != nil {
			t.Fatalf("newLeaseRegistry() error = %v", registryErr)
		}
		return registry
	}
	// The same relay identity in a fresh registry simulates a relay restart:
	// tokens stay verifiable while the in-memory lease records are gone.
	before, restarted := newRegistry(), newRegistry()

	_, resp, err := before.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "restart")}, "203.0.113.10", "", types.RelayDescriptor{}, nil)
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
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: resp.AccessToken}, "203.0.113.10"); !errors.Is(err, errLeaseNotFound) {
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
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: "forged"}, "203.0.113.10"); !errors.Is(err, errUnauthorized) {
		t.Fatalf("Renew() forged = %v, want unauthorized", err)
	}
}
