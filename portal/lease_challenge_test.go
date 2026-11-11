package portal

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestLeaseRegistryPolicyViewsUsePushedAccess(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "demo")
	registry.setIdentityAccess(identity.ServiceKey(), types.LeasePending, 1)
	record, resp, err := registry.Register(types.RegisterChallengeRequest{
		Identity: identity,
	}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	checkHiddenPushedViews(t, registry, resp.AccessToken)
	checkRoutableLeaseVisible(t, registry, record.ServiceKey(), resp.AccessToken)
}

func TestRefusalNamesTheAccessDecision(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "refusal")
	record, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(record.Close)
	key := leaseIdentity.ServiceKey()
	for revision, tc := range []struct {
		access types.LeaseAccess
		want   error
	}{
		{types.LeasePending, errLeaseRejected},
		{types.LeaseDenied, errLeaseDenied},
		{types.LeaseRoutable, nil},
		{"", errLeaseRejected},
	} {
		registry.setIdentityAccess(key, tc.access, uint64(revision+1))
		if _, err := registry.admitLeaseByToken(lease.AccessToken, false); !errors.Is(err, tc.want) {
			t.Fatalf("%q admission = %v, want %v", tc.access, err, tc.want)
		}
	}
}

func TestRoutingDecisionControlsIdleReverseStreams(t *testing.T) {
	registry, record, key := seedIdleReverseStreamLease(t)
	if err := offerIdleReverseStream(t, record); err != nil {
		t.Fatal(err)
	}
	checkSuspendedStreamParked(t, registry, key, record)
	checkPendingStreamDropped(t, registry, key, record)
	checkRoutableStreamAdmitted(t, registry, key, record)
}

func TestUnapprovedLeaseLimitBoundsOneSource(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	registry.unapprovedPerSource = 2
	source := netip.MustParseAddr("203.0.113.20")
	other := netip.MustParseAddr("203.0.113.21")
	first, second, firstLease := seedUnapprovedSlotLeases(t, registry, source)
	newcomer := checkUnapprovedSlotBurst(t, registry, source)
	checkUnapprovedSlotRepeat(t, registry, first, source)
	checkUnapprovedSlotOtherSource(t, registry, newcomer, other)
	renewUnapprovedSlotLease(t, registry, firstLease, other)
	touchUnapprovedSlotLease(t, registry, second, other)
	checkUnapprovedSlotStillBound(t, registry, newcomer, source)
	checkUnapprovedSlotUnknownSource(t, registry, newcomer)
	checkUnapprovedSlotFreed(t, registry, first, newcomer, source)
	checkUnapprovedSlotZeroLimit(t, registry, first, newcomer, source)
}

func TestUnapprovedLeaseLimitCountsPendingChallenges(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	registry.unapprovedPerSource = 2
	source := netip.MustParseAddr("203.0.113.20")
	other := netip.MustParseAddr("203.0.113.21")
	checkPendingChallengeBurst(t, registry, source, other)
	checkPendingChallengeSharedSlot(t, registry, other)
}

func TestAccessRevisionRejectsInFlightAllow(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "revision")
	_, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := leaseIdentity.ServiceKey()
	registry.setIdentityAccess(key, types.LeaseRoutable, 1)
	rejectStaleAllowRevision(t, registry, key)
	checkStaleAllowDenied(t, registry, lease.AccessToken)
	checkStaleAllowRestored(t, registry, key, lease.AccessToken)
}

func TestAccessRevisionSurvivesIdleCleanupAndRegistration(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	key := types.NewServiceIdentityKey("revision", "identity")
	registry.setIdentityAccess(key, types.LeasePending, 2)
	registry.cleanupExpired(time.Now().Add(defaultRegisterChallengeTTL + time.Second))
	if registry.setIdentityAccess(key, types.LeaseRoutable, 1) {
		t.Fatal("idle cleanup forgot the revision fence")
	}
	registry.setIdentityAccess(key, types.LeaseRoutable, 3)
	registry.suspendIdentity(key)
	if registry.isRoutable(key) {
		t.Fatal("registration was not fail-closed")
	}
	if registry.setIdentityAccess(key, types.LeaseRoutable, 2) {
		t.Fatal("registration accepted an older revision")
	}
	if !registry.setIdentityAccess(key, types.LeaseRoutable, 3) || !registry.isRoutable(key) {
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
				issuePendingChallenge(t, registry, request, sourceAddr, i)
				if tc.name == "global" {
					sourceAddr = sourceAddr.Next()
				}
			}
			checkPendingChallengeRejected(t, registry, request, sourceAddr, tc.limit)
			checkPendingChallengeExpired(t, registry, request, sourceAddr)
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
		registry, registryErr := newLeaseRegistry(0, 0, relay.Name, relayAuthority, "https://example.com", 0)
		if registryErr != nil {
			t.Fatalf("newLeaseRegistry() error = %v", registryErr)
		}
		return registry
	}
	before, restarted := newRegistry(), newRegistry()
	resp := registerRestartLease(t, before)
	checkRestartedLeaseNotFound(t, restarted, resp)
	checkForgedLeaseUnauthorized(t, restarted)
}

func checkHiddenPushedViews(t *testing.T, registry *leaseRegistry, token string) {
	t.Helper()
	if leases := registry.PublicLeases(time.Now()); len(leases) != 0 {
		t.Fatalf("PublicLeases() length = %d, want 0 while not routable", len(leases))
	}
	if _, err := registry.admitLeaseByToken(token, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("admitLeaseByToken() error = %v, want lease rejected while not routable", err)
	}
}

func checkRoutableLeaseVisible(t *testing.T, registry *leaseRegistry, identityKey types.ServiceIdentityKey, token string) {
	t.Helper()
	registry.setIdentityAccess(identityKey, types.LeaseRoutable, 2)
	if leases := registry.PublicLeases(time.Now()); len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 after the relay routes the identity", len(leases))
	}
	if _, err := registry.admitLeaseByToken(token, false); err != nil {
		t.Fatalf("admitLeaseByToken() error = %v, want admitted once routable", err)
	}
}

func seedIdleReverseStreamLease(t *testing.T) (*leaseRegistry, *leaseRecord, types.ServiceIdentityKey) {
	t.Helper()
	registry := newTestRegistry(t, false, false)
	leaseIdentity := newTestLeaseIdentity(t, "streams")
	record, _, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(record.Close)
	key := leaseIdentity.ServiceKey()
	registry.setIdentityAccess(key, types.LeaseRoutable, 1)
	return registry, record, key
}

func offerIdleReverseStream(t *testing.T, record *leaseRecord) error {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	return record.reverse.Offer(local)
}

func checkSuspendedStreamParked(t *testing.T, registry *leaseRegistry, key types.ServiceIdentityKey, record *leaseRecord) {
	t.Helper()
	registry.suspendIdentity(key)
	if record.reverse.ReadyCount() != 1 {
		t.Fatal("suspending the identity dropped its idle stream")
	}
}

func checkPendingStreamDropped(t *testing.T, registry *leaseRegistry, key types.ServiceIdentityKey, record *leaseRecord) {
	t.Helper()
	registry.setIdentityAccess(key, types.LeasePending, 2)
	if record.reverse.ReadyCount() != 0 {
		t.Fatal("a non-routable decision left an idle stream parked")
	}
	if err := offerIdleReverseStream(t, record); err == nil {
		t.Fatal("a non-routable lease accepted a reverse stream")
	}
}

func checkRoutableStreamAdmitted(t *testing.T, registry *leaseRegistry, key types.ServiceIdentityKey, record *leaseRecord) {
	t.Helper()
	registry.setIdentityAccess(key, types.LeaseRoutable, 3)
	if err := offerIdleReverseStream(t, record); err != nil {
		t.Fatalf("a routable lease refused a reverse stream: %v", err)
	}
	if record.reverse.ReadyCount() != 1 {
		t.Fatal("a routable decision did not admit the stream")
	}
}

func askUnapprovedSlotChallenge(t *testing.T, registry *leaseRegistry, leaseIdentity types.Identity, from netip.Addr) (types.RegisterChallengeResponse, error) {
	t.Helper()
	challenge, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{Identity: leaseIdentity}, "example.com", "https://example.com"+types.PathSDKRegister, from)
	if err != nil {
		t.Fatal(err)
	}
	return challenge, registry.refuseChallengeOverBudget(leaseIdentity.ServiceKey(), challenge.ChallengeID, from)
}

func registerUnapprovedSlotLease(t *testing.T, registry *leaseRegistry, leaseIdentity types.Identity, from netip.Addr) types.RegisterResponse {
	t.Helper()
	issued, err := askUnapprovedSlotChallenge(t, registry, leaseIdentity, from)
	if err != nil {
		t.Fatalf("%s: %v", leaseIdentity.Name, err)
	}
	signature, err := identity.NewLocalAuthority(leaseIdentity).SignEthereumPersonalMessage(issued.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	challenge, asked, err := registry.consumeVerifiedRegisterChallenge(types.RegisterRequest{ChallengeID: issued.ChallengeID, SIWEMessage: issued.SIWEMessage, SIWESignature: signature})
	if err != nil {
		t.Fatalf("%s: %v", leaseIdentity.Name, err)
	}
	if asked != from {
		t.Fatalf("%s: challenge source = %v; want %v", leaseIdentity.Name, asked, from)
	}
	record, registered, err := registry.Register(challenge.Request, asked, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(record.Close)
	return registered
}

func seedUnapprovedSlotLeases(t *testing.T, registry *leaseRegistry, source netip.Addr) (types.Identity, types.Identity, types.RegisterResponse) {
	t.Helper()
	first := newTestLeaseIdentity(t, "first")
	registry.setIdentityAccess(first.ServiceKey(), types.LeasePending, 1)
	firstLease := registerUnapprovedSlotLease(t, registry, first, source)
	second := newTestLeaseIdentity(t, "second")
	registry.setIdentityAccess(second.ServiceKey(), types.LeaseDenied, 2)
	registerUnapprovedSlotLease(t, registry, second, source)
	approved := newTestLeaseIdentity(t, "approved")
	registry.setIdentityAccess(approved.ServiceKey(), types.LeaseRoutable, 3)
	registerUnapprovedSlotLease(t, registry, approved, source)
	return first, second, firstLease
}

func checkUnapprovedSlotBurst(t *testing.T, registry *leaseRegistry, source netip.Addr) types.Identity {
	t.Helper()
	newcomer := newTestLeaseIdentity(t, "third")
	registry.setIdentityAccess(newcomer.ServiceKey(), types.LeasePending, 4)
	for range defaultRegisterChallengeOutstandingPerIP + 1 {
		if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, source); !errors.Is(err, errUnapprovedLeaseLimit) {
			t.Fatalf("third unapproved lease = %v", err)
		}
	}
	return newcomer
}

func checkUnapprovedSlotRepeat(t *testing.T, registry *leaseRegistry, first types.Identity, source netip.Addr) {
	t.Helper()
	if _, err := askUnapprovedSlotChallenge(t, registry, first, source); err != nil {
		t.Fatalf("a repeat registration counted against itself: %v", err)
	}
}

func checkUnapprovedSlotOtherSource(t *testing.T, registry *leaseRegistry, newcomer types.Identity, other netip.Addr) {
	t.Helper()
	if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, other); err != nil {
		t.Fatalf("another source was refused: %v", err)
	}
}

func renewUnapprovedSlotLease(t *testing.T, registry *leaseRegistry, firstLease types.RegisterResponse, other netip.Addr) {
	t.Helper()
	if _, _, err := registry.Renew(types.RenewRequest{AccessToken: firstLease.AccessToken, TTL: 60}, other, nil); err != nil {
		t.Fatal(err)
	}
}

func touchUnapprovedSlotLease(t *testing.T, registry *leaseRegistry, second types.Identity, other netip.Addr) {
	t.Helper()
	registry.Touch(second.ServiceKey(), other, time.Now())
}

func checkUnapprovedSlotStillBound(t *testing.T, registry *leaseRegistry, newcomer types.Identity, source netip.Addr) {
	t.Helper()
	if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, source); !errors.Is(err, errUnapprovedLeaseLimit) {
		t.Fatalf("a renew from elsewhere freed a slot: %v", err)
	}
}

func checkUnapprovedSlotUnknownSource(t *testing.T, registry *leaseRegistry, newcomer types.Identity) {
	t.Helper()
	for revision, name := range []string{"unknown-first", "unknown-second"} {
		unknown := newTestLeaseIdentity(t, name)
		registry.setIdentityAccess(unknown.ServiceKey(), types.LeasePending, uint64(revision+5))
		registerUnapprovedSlotLease(t, registry, unknown, netip.Addr{})
	}
	if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, netip.Addr{}); err != nil {
		t.Fatalf("an unknown source must fail open: %v", err)
	}
}

func checkUnapprovedSlotFreed(t *testing.T, registry *leaseRegistry, first types.Identity, newcomer types.Identity, source netip.Addr) {
	t.Helper()
	registry.setIdentityAccess(first.ServiceKey(), types.LeaseRoutable, 7)
	if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, source); err != nil {
		t.Fatalf("the refused identity did not pass once a slot freed: %v", err)
	}
}

func checkUnapprovedSlotZeroLimit(t *testing.T, registry *leaseRegistry, first types.Identity, newcomer types.Identity, source netip.Addr) {
	t.Helper()
	registry.setIdentityAccess(first.ServiceKey(), types.LeasePending, 8)
	registry.unapprovedPerSource = 0
	if _, err := askUnapprovedSlotChallenge(t, registry, newcomer, source); err != nil {
		t.Fatalf("a zero limit must disable the bound: %v", err)
	}
}

func askPendingChallengeBudget(t *testing.T, registry *leaseRegistry, revision uint64, from netip.Addr) error {
	t.Helper()
	leaseIdentity := newTestLeaseIdentity(t, fmt.Sprintf("burst-%d", revision))
	registry.setIdentityAccess(leaseIdentity.ServiceKey(), types.LeasePending, revision)
	challenge, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{Identity: leaseIdentity}, "example.com", "https://example.com"+types.PathSDKRegister, from)
	if err != nil {
		t.Fatal(err)
	}
	return registry.refuseChallengeOverBudget(leaseIdentity.ServiceKey(), challenge.ChallengeID, from)
}

func checkPendingChallengeBurst(t *testing.T, registry *leaseRegistry, source netip.Addr, other netip.Addr) {
	t.Helper()
	for revision := range uint64(2) {
		if err := askPendingChallengeBudget(t, registry, revision+1, source); err != nil {
			t.Fatal(err)
		}
	}
	if err := askPendingChallengeBudget(t, registry, 3, source); !errors.Is(err, errUnapprovedLeaseLimit) {
		t.Fatalf("third challenge of the burst = %v", err)
	}
	if err := askPendingChallengeBudget(t, registry, 4, other); err != nil {
		t.Fatalf("another source's challenges counted: %v", err)
	}
}

func checkPendingChallengeSharedSlot(t *testing.T, registry *leaseRegistry, other netip.Addr) {
	t.Helper()
	registry.unapprovedPerSource = 3
	again := newTestLeaseIdentity(t, "burst-twice")
	registry.setIdentityAccess(again.ServiceKey(), types.LeasePending, 5)
	for range 2 {
		if _, err := registry.issueRegisterChallenge(types.RegisterChallengeRequest{Identity: again}, "example.com", "https://example.com"+types.PathSDKRegister, other); err != nil {
			t.Fatal(err)
		}
	}
	if err := askPendingChallengeBudget(t, registry, 6, other); err != nil {
		t.Fatalf("one identity took two slots: %v", err)
	}
}

func rejectStaleAllowRevision(t *testing.T, registry *leaseRegistry, key types.ServiceIdentityKey) {
	t.Helper()
	loaded := make(chan struct{})
	resume := make(chan struct{})
	applied := make(chan bool, 1)
	go func() {
		close(loaded)
		<-resume
		applied <- registry.setIdentityAccess(key, types.LeaseRoutable, 1)
	}()
	<-loaded
	registry.setIdentityAccess(key, types.LeasePending, 2)
	close(resume)
	if <-applied {
		t.Fatal("stale allow was applied after the newer denial")
	}
}

func checkStaleAllowDenied(t *testing.T, registry *leaseRegistry, token string) {
	t.Helper()
	if _, err := registry.admitLeaseByToken(token, false); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("delayed allow bypassed denial: %v", err)
	}
}

func checkStaleAllowRestored(t *testing.T, registry *leaseRegistry, key types.ServiceIdentityKey, token string) {
	t.Helper()
	registry.setIdentityAccess(key, types.LeaseRoutable, 3)
	if _, err := registry.admitLeaseByToken(token, false); err != nil {
		t.Fatalf("newer allow failed to restore access: %v", err)
	}
}

func checkPendingChallengeRejected(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, sourceAddr netip.Addr, limit int) {
	t.Helper()
	if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr); !errors.Is(err, errRegisterChallengePending) {
		t.Fatalf("issueRegisterChallenge() error = %v, want pending limit", err)
	}
	if len(registry.records) != limit {
		t.Fatal("rejected challenge was retained")
	}
}

func checkPendingChallengeExpired(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, sourceAddr netip.Addr) {
	t.Helper()
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
}

func registerRestartLease(t *testing.T, before *leaseRegistry) types.RegisterResponse {
	t.Helper()
	_, resp, err := before.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "restart")}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.AccessToken == "" || resp.ReverseEndpoint.Capability == "" {
		t.Fatalf("register response missing credentials: %+v", resp)
	}
	return resp
}

func checkRestartedLeaseNotFound(t *testing.T, restarted *leaseRegistry, resp types.RegisterResponse) {
	t.Helper()
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
}

func checkForgedLeaseUnauthorized(t *testing.T, restarted *leaseRegistry) {
	t.Helper()
	if _, err := restarted.admitReverseCapability("forged"); !errors.Is(err, errUnauthorized) {
		t.Fatalf("admitReverseCapability() forged = %v, want unauthorized", err)
	}
	if _, _, err := restarted.Renew(types.RenewRequest{AccessToken: "forged"}, netip.MustParseAddr("203.0.113.10"), nil); !errors.Is(err, errUnauthorized) {
		t.Fatalf("Renew() forged = %v, want unauthorized", err)
	}
}

func issuePendingChallenge(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, sourceAddr netip.Addr, i int) {
	t.Helper()
	if _, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, sourceAddr); err != nil {
		t.Fatalf("issueRegisterChallenge(%d) error = %v", i, err)
	}
}
