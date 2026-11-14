package portal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestLeaseRegistryPolicyViewsUsePushedAccess(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	identity := newTestLeaseIdentity(t, "demo")
	registry.setIdentityAccess(identity.ServiceKey(), types.LeasePending, 1)
	record, _, resp, err := registry.Register(types.RegisterChallengeRequest{
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
	record, _, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
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
	_, _, lease, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
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
	record, _, _, err := registry.Register(types.RegisterChallengeRequest{
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
	record, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: leaseIdentity}, netip.MustParseAddr("203.0.113.20"), "", types.RelayDescriptor{}, nil, nil)
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
	record, _, registered, err := registry.Register(challenge.Request, asked, "", types.RelayDescriptor{}, nil, nil)
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
	_, _, resp, err := before.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "restart")}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
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
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	checkHostnameConflictFreesPorts(t, registry, request)
	request.Identity = newTestLeaseIdentity(t, "accepted")
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("rejected identities exhausted raw ports: %v", err)
	}
}

func checkHostnameConflictFreesPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	for i := range 3 {
		request.Identity = newTestLeaseIdentity(t, "conflict")
		if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errHostnameConflict) {
			t.Fatalf("rejected registration %d error = %v, want hostname conflict", i, err)
		}
		if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
			len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
			t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
		}
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
			if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if tc.limitUDP {
				registry.setTransportPolicy(true, 1, true, 0)
			} else {
				registry.setTransportPolicy(true, 0, true, 1)
			}
			checkCapacityRejectionFreesPorts(t, registry, request, tc.wantError)
			registry.setTransportPolicy(true, 2, true, 2)
			request.Identity = newTestLeaseIdentity(t, "accepted")
			if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
				t.Fatalf("capacity rejection exhausted raw ports: %v", err)
			}
		})
	}
}

func checkCapacityRejectionFreesPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, wantError error) {
	t.Helper()
	for i := range 3 {
		request.Identity = newTestLeaseIdentity(t, fmt.Sprintf("rejected-%d", i))
		if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, wantError) {
			t.Fatalf("rejected registration %d error = %v, want %v", i, err, wantError)
		}
		if len(registry.udpPorts.available) != 1 || len(registry.tcpPorts.available) != 1 ||
			len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
			t.Fatalf("rejected registration %d retained ports: UDP=%+v TCP=%+v", i, registry.udpPorts, registry.tcpPorts)
		}
	}
}

func TestLeaseTCPPortExhaustionRollsBackAllocatedUDPPort(t *testing.T) {
	registry := newTestRegistry(t, true, true)
	seedLeaseTCPPortsExhaustionPair(t, registry)
	both := types.RegisterChallengeRequest{
		Identity:   newTestLeaseIdentity(t, "both"),
		UDPEnabled: true,
		TCPEnabled: true,
	}
	rejectExhaustedTCPFreesUDP(t, registry, both)
	acceptUDPOnlyAfterExhaustion(t, registry, both)
}

func seedLeaseTCPPortsExhaustionPair(t *testing.T, registry *leaseRegistry) {
	t.Helper()
	for i := range 2 {
		request := types.RegisterChallengeRequest{
			Identity:   newTestLeaseIdentity(t, fmt.Sprintf("tcp-%d", i)),
			TCPEnabled: true,
		}
		if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func rejectExhaustedTCPFreesUDP(t *testing.T, registry *leaseRegistry, both types.RegisterChallengeRequest) {
	t.Helper()
	if _, _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
		t.Fatalf("Register() error = %v, want TCP port exhaustion", err)
	}
	if len(registry.udpPorts.available) != 2 || len(registry.udpPorts.reserved) != 0 {
		t.Fatalf("failed TCP allocation retained a UDP port: %+v", registry.udpPorts)
	}
}

func acceptUDPOnlyAfterExhaustion(t *testing.T, registry *leaseRegistry, both types.RegisterChallengeRequest) {
	t.Helper()
	both.TCPEnabled = false
	both.Identity = newTestLeaseIdentity(t, "udp")
	if _, _, _, err := registry.Register(both, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
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
	firstRecord, first := registerFirstStickyLease(t, registry, request)
	rejectStickyPortsOtherOwner(t, registry, request, first)
	reconnectStickyLeaseKeepsPorts(t, registry, request, first)
	verifyStaleCleanupKeepsPorts(t, registry, firstRecord, request)
}

func registerFirstStickyLease(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) (*leaseRecord, types.RegisterResponse) {
	t.Helper()
	firstRecord, _, first, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: first.AccessToken}); err != nil {
		t.Fatal(err)
	}
	return firstRecord, first
}

func rejectStickyPortsOtherOwner(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, first types.RegisterResponse) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "shared")
	_, _, other, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
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
}

func reconnectStickyLeaseKeepsPorts(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, first types.RegisterResponse) {
	t.Helper()
	_, _, reconnected, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.UDPAddr != first.UDPAddr || reconnected.TCPAddr != first.TCPAddr {
		t.Fatalf("reconnect lost reserved addresses: got %s/%s, want %s/%s", reconnected.UDPAddr, reconnected.TCPAddr, first.UDPAddr, first.TCPAddr)
	}
}

func verifyStaleCleanupKeepsPorts(t *testing.T, registry *leaseRegistry, firstRecord *leaseRecord, request types.RegisterChallengeRequest) {
	t.Helper()
	registry.closeRecord(firstRecord)
	request.Identity = newTestLeaseIdentity(t, "third")
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errUDPPortExhausted) {
		t.Fatalf("stale cleanup released a live UDP port: %v", err)
	}
	request.UDPEnabled = false
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); !errors.Is(err, errTCPPortExhausted) {
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
			if network == "tcp" {
				occupied = listenOccupiedTCPPort(t, port)
			} else {
				occupied = listenOccupiedUDPPort(t, port)
			}
			defer occupied.Close()
			rejectOccupiedPortWithoutReserve(t, registry, request)
			registerOtherIdentitySucceeds(t, registry, request)
			_ = occupied.Close()
			reuseRecoveredPortAfterClose(t, registry, request, port)
		})
	}
}

func listenOccupiedTCPPort(t *testing.T, port int) io.Closer {
	t.Helper()
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return occupied
}

func listenOccupiedUDPPort(t *testing.T, port int) io.Closer {
	t.Helper()
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return occupied
}

func rejectOccupiedPortWithoutReserve(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err == nil {
		t.Fatal("registration succeeded with an occupied port")
	}
	if len(registry.udpPorts.reserved) != 0 || len(registry.tcpPorts.reserved) != 0 {
		t.Fatal("socket start failure created sticky port reservations")
	}
}

func registerOtherIdentitySucceeds(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "different")
	if _, _, _, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("occupied port prevented another identity using free ports: %v", err)
	}
}

func reuseRecoveredPortAfterClose(t *testing.T, registry *leaseRegistry, request types.RegisterChallengeRequest, port int) {
	t.Helper()
	request.Identity = newTestLeaseIdentity(t, "recovered")
	_, _, response, err := registry.Register(request, netip.Addr{}, "", types.RelayDescriptor{}, nil, nil)
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
}

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

func TestLeaseBridgeCapacityAndRevocation(t *testing.T) {
	record := &leaseRecord{Identity: types.Identity{Name: "lease", Address: "0x1"}, ExpiresAt: time.Now().Add(time.Hour), reverse: transport.NewReversePool(time.Minute, 1)}
	defer record.Close()
	registry := &leaseRegistry{records: []*leaseRecord{record}, blocked: make(map[types.ServiceIdentityKey]blockedIdentity)}
	bridges := admitCapacityBridges(t, registry, record)
	defer releaseCapacityBridges(record, bridges)
	excess, peer := net.Pipe()
	defer excess.Close()
	defer peer.Close()
	checkBridgeOverLimit(t, registry, record, excess)
	revokeCapacityBridges(t, registry, record, bridges)
	checkBridgeCapacityRecovered(t, registry, record, excess, bridges)
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
	record, _, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "renew-bridge")}, netip.MustParseAddr("127.0.0.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		renewLeaseConcurrently(t, registry, registered.AccessToken)
	})
	workers.Go(func() {
		admitBridgesConcurrently(t, registry, record)
	})
	workers.Wait()
}

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
			registered, err := registerLeftBehindLease(t, registry, tenant, test.registered)
			if err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			renewErr := renewLeftBehindLease(t, registry, types.RenewRequest{AccessToken: registered.AccessToken, TTL: 600, RepinsChain: test.repins}, test.current)
			record := lookupLeftBehindLease(t, registry, registered.CanonicalHostname)
			if test.wantRenewed {
				checkRenewedLeftBehindLease(t, registered, record, renewErr)
				return
			}
			checkStaleLeftBehindLease(t, registered, record, renewErr)
			reregisterLeftBehindLease(t, registry, tenant, test.current)
		})
	}
}

func TestRenewJudgesAgainstTheChainTheLeaseRegisteredUnder(t *testing.T) {
	t.Parallel()

	root := newTestRelayIntermediate(t, "Root")
	first, second := root.subordinate(t, "R10"), root.subordinate(t, "R11")
	pinned := first.issue(t, "example.com")
	withRoot := first.issue(t, "example.com", root.cert)
	otherIssuer := second.issue(t, "example.com")

	registry := newTestRegistry(t, false, false)
	_, _, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "tenant")}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, pinned)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	renew := func(current *acme.TLSMaterial) error {
		_, _, err := registry.Renew(types.RenewRequest{AccessToken: registered.AccessToken, TTL: 600}, netip.MustParseAddr("203.0.113.10"), current)
		return err
	}
	if err := renew(withRoot); err != nil {
		t.Fatalf("Renew() with a chain the pinned one verifies = %v, want the lease renewed", err)
	}
	if err := renew(otherIssuer); !errors.Is(err, errLeaseNotFound) {
		t.Fatalf("Renew() with a chain only the root of the earlier bundle verifies = %v, want lease_not_found", err)
	}
}

type testRelayIntermediate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestRelayIntermediate(t *testing.T, name string) testRelayIntermediate {
	t.Helper()
	return newTestRelayCA(t, name, nil)
}

func (i testRelayIntermediate) subordinate(t *testing.T, name string) testRelayIntermediate {
	t.Helper()
	return newTestRelayCA(t, name, &i)
}

func newTestRelayCA(t *testing.T, name string, issuer *testRelayIntermediate) testRelayIntermediate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := newRelayCACertTemplate(name)
	parent, parentKey := template, key
	if issuer != nil {
		parent, parentKey = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testRelayIntermediate{cert: cert, key: key}
}

func (i testRelayIntermediate) issue(t *testing.T, host string, extra ...*x509.Certificate) *acme.TLSMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := buildLeafCertTemplate(host)
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw})...)
	for _, certificate := range extra {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	certificate, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &acme.TLSMaterial{CertPEM: certPEM, Certificate: certificate}
}

func TestRegisterPreservesStartedAtAndFirstSeenAt(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	id := newTestLeaseIdentity(t, "started-at")
	clientStartedAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	checkInitialFirstSeen(t, registry, id, clientStartedAt)
	record2 := checkReconnectFirstSeen(t, registry, id, clientStartedAt)
	checkLiveReplacementFirstSeen(t, registry, record2, id, clientStartedAt)
	expireStartedAtLeases(t, registry, id)
	checkExpiredReplacementFirstSeen(t, registry, id)
	checkFutureStartedAtClamped(t, registry)
	checkAncientStartedAtFloored(t, registry)
}

func TestLookupRejectsHostnameNoLeaseHolds(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if _, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "lookup-guard"),
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, ok := registry.Lookup("no-lease-holds-this-hostname-xyz"); ok {
		t.Fatal("Lookup(unheld hostname) = true, want false")
	}
}

func TestPublicLeasesOmitsHiddenLease(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t, false, false)
	if _, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "hidden-lease"),
		Metadata: types.LeaseMetadata{Hide: true},
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if _, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: newTestLeaseIdentity(t, "shown-lease"),
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1 with the hidden lease omitted", len(leases))
	}
}

func admitCapacityBridges(t *testing.T, registry *leaseRegistry, record *leaseRecord) []*leaseBridge {
	t.Helper()
	var bridges []*leaseBridge
	for index := range defaultLeaseBridgeLimit {
		inbound, peer := net.Pipe()
		bridge, err := registry.admitBridge(t.Context(), record, inbound)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		if index < 16 {
			reverse, other := net.Pipe()
			t.Cleanup(func() { _ = other.Close() })
			if err := registry.activateBridge(record, bridge, reverse); err != nil {
				t.Fatal(err)
			}
		}
		bridges = append(bridges, bridge)
	}
	return bridges
}

func releaseCapacityBridges(record *leaseRecord, bridges []*leaseBridge) {
	for i := len(bridges) - 1; i >= 0; i-- {
		record.releaseBridge(bridges[i])
	}
}

func checkBridgeOverLimit(t *testing.T, registry *leaseRegistry, record *leaseRecord, excess net.Conn) {
	t.Helper()
	if _, err := registry.admitBridge(t.Context(), record, excess); !errors.Is(err, errLeaseRejected) {
		t.Fatalf("capacity admission = %v", err)
	}
}

func revokeCapacityBridges(t *testing.T, registry *leaseRegistry, record *leaseRecord, bridges []*leaseBridge) {
	t.Helper()
	registry.setIdentityAccess(record.ServiceKey(), types.LeasePending, 1)
	registry.setIdentityAccess(record.ServiceKey(), types.LeaseRoutable, 2)
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
}

func checkBridgeCapacityRecovered(t *testing.T, registry *leaseRegistry, record *leaseRecord, excess net.Conn, bridges []*leaseBridge) {
	t.Helper()
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

func renewLeaseConcurrently(t *testing.T, registry *leaseRegistry, token string) {
	t.Helper()
	for range 100 {
		if _, _, err := registry.Renew(types.RenewRequest{AccessToken: token, TTL: 120}, netip.Addr{}, nil); err != nil {
			t.Error(err)
			return
		}
	}
}

func admitBridgesConcurrently(t *testing.T, registry *leaseRegistry, record *leaseRecord) {
	t.Helper()
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
}

func registerLeftBehindLease(t *testing.T, registry *leaseRegistry, tenant types.Identity, served *acme.TLSMaterial) (types.RegisterResponse, error) {
	t.Helper()
	record, _, registered, err := registry.Register(types.RegisterChallengeRequest{Identity: tenant}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, served)
	if err != nil {
		return types.RegisterResponse{}, err
	}
	t.Cleanup(record.Close)
	return registered, nil
}

func renewLeftBehindLease(t *testing.T, registry *leaseRegistry, req types.RenewRequest, current *acme.TLSMaterial) error {
	t.Helper()
	_, _, err := registry.Renew(req, netip.MustParseAddr("203.0.113.10"), current)
	return err
}

func lookupLeftBehindLease(t *testing.T, registry *leaseRegistry, hostname string) *leaseRecord {
	t.Helper()
	record, ok := registry.Lookup(hostname)
	if !ok {
		t.Fatal("Lookup() found no lease after Renew()")
	}
	return record
}

func checkRenewedLeftBehindLease(t *testing.T, registered types.RegisterResponse, record *leaseRecord, renewErr error) {
	t.Helper()
	if renewErr != nil || !record.ExpiresAt.After(registered.ExpiresAt) {
		t.Fatalf("Renew() = %v, expiry %v; want the lease renewed past %v", renewErr, record.ExpiresAt, registered.ExpiresAt)
	}
}

func checkStaleLeftBehindLease(t *testing.T, registered types.RegisterResponse, record *leaseRecord, renewErr error) {
	t.Helper()
	if !errors.Is(renewErr, errLeaseNotFound) || !record.ExpiresAt.Equal(registered.ExpiresAt) {
		t.Fatalf("Renew() = %v, expiry %v; want lease_not_found and the lease left to expire at %v", renewErr, record.ExpiresAt, registered.ExpiresAt)
	}
}

func newRelayCACertTemplate(name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func buildLeafCertTemplate(host string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host, "*." + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func checkInitialFirstSeen(t *testing.T, registry *leaseRegistry, id types.Identity, clientStartedAt time.Time) {
	t.Helper()
	record1, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity:  id,
		StartedAt: clientStartedAt,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !record1.FirstSeenAt.Equal(clientStartedAt) {
		t.Fatalf("FirstSeenAt = %v, want %v", record1.FirstSeenAt, clientStartedAt)
	}
	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 || !leases[0].FirstSeenAt.Equal(clientStartedAt) {
		t.Fatalf("PublicLeases() first_seen_at = %v, want %v", leases[0].FirstSeenAt, clientStartedAt)
	}
}

func checkReconnectFirstSeen(t *testing.T, registry *leaseRegistry, id types.Identity, clientStartedAt time.Time) *leaseRecord {
	t.Helper()
	record2, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: id,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() reconnect error = %v", err)
	}
	if !record2.FirstSeenAt.Equal(clientStartedAt) {
		t.Fatalf("FirstSeenAt after reconnect without started_at = %v, want %v", record2.FirstSeenAt, clientStartedAt)
	}
	return record2
}

func checkLiveReplacementFirstSeen(t *testing.T, registry *leaseRegistry, record2 *leaseRecord, id types.Identity, clientStartedAt time.Time) {
	t.Helper()
	observedAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	registry.mu.Lock()
	record2.FirstSeenAt = observedAt
	registry.mu.Unlock()
	for _, startedAt := range []time.Time{{}, clientStartedAt, time.Now().UTC().Add(-2 * time.Minute)} {
		record3, _, _, err := registry.Register(types.RegisterChallengeRequest{
			Identity:  id,
			StartedAt: startedAt,
		}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatalf("Register() live replacement error = %v", err)
		}
		if !record3.FirstSeenAt.Equal(observedAt) {
			t.Fatalf("FirstSeenAt after live replacement with started_at %v = %v, want %v", startedAt, record3.FirstSeenAt, observedAt)
		}
	}
}

func expireStartedAtLeases(t *testing.T, registry *leaseRegistry, id types.Identity) {
	t.Helper()
	registry.mu.Lock()
	for _, existing := range registry.records {
		if existing != nil && existing.ServiceKey() == id.ServiceKey() {
			existing.ExpiresAt = time.Now().Add(-time.Second)
		}
	}
	registry.mu.Unlock()
}

func checkExpiredReplacementFirstSeen(t *testing.T, registry *leaseRegistry, id types.Identity) {
	t.Helper()
	beforeExpired := time.Now().UTC().Truncate(time.Second)
	expiredRecord, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity: id,
	}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() after expiry error = %v", err)
	}
	if expiredRecord.FirstSeenAt.Before(beforeExpired) {
		t.Fatalf("FirstSeenAt after expired replacement = %v, want no earlier than %v", expiredRecord.FirstSeenAt, beforeExpired)
	}
}

func checkFutureStartedAtClamped(t *testing.T, registry *leaseRegistry) {
	t.Helper()
	futureID := newTestLeaseIdentity(t, "future-started")
	futureStartedAt := time.Now().UTC().Add(10 * time.Minute)
	beforeReg := time.Now().UTC().Truncate(time.Second)
	record4, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity:  futureID,
		StartedAt: futureStartedAt,
	}, netip.MustParseAddr("203.0.113.11"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() future error = %v", err)
	}
	afterReg := time.Now().UTC().Add(time.Second)
	if record4.FirstSeenAt.Before(beforeReg) || record4.FirstSeenAt.After(afterReg) {
		t.Fatalf("FirstSeenAt for future StartedAt was %v, want clamped between %v and %v", record4.FirstSeenAt, beforeReg, afterReg)
	}
}

func checkAncientStartedAtFloored(t *testing.T, registry *leaseRegistry) {
	t.Helper()
	oldID := newTestLeaseIdentity(t, "ancient-started")
	record5, _, _, err := registry.Register(types.RegisterChallengeRequest{
		Identity:  oldID,
		StartedAt: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
	}, netip.MustParseAddr("203.0.113.12"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatalf("Register() ancient error = %v", err)
	}
	floor := time.Now().UTC().Add(-maxClaimedStartedAge - time.Minute)
	if record5.FirstSeenAt.Before(floor) {
		t.Fatalf("FirstSeenAt for ancient StartedAt = %v, want no earlier than %v", record5.FirstSeenAt, floor)
	}
}

func reregisterLeftBehindLease(t *testing.T, registry *leaseRegistry, tenant types.Identity, current *acme.TLSMaterial) {
	t.Helper()
	again, err := registerLeftBehindLease(t, registry, tenant, current)
	if err != nil {
		t.Fatalf("Register() again error = %v", err)
	}
	if err := renewLeftBehindLease(t, registry, types.RenewRequest{AccessToken: again.AccessToken, TTL: 600}, current); err != nil {
		t.Fatalf("Renew() after registering again = %v, want the lease renewed", err)
	}
}

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
	registry, err := newLeaseRegistry(minPort, maxPort, relay.Name, relayAuthority, "https://example.com", 0)
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	registry.setTransportPolicy(udpEnabled, 0, tcpPortEnabled, 0)
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
		listeners, available := reserveEphemeralListeners(minPort, maxPort, first)
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

func reserveEphemeralListeners(minPort, maxPort int, first io.Closer) ([]io.Closer, bool) {
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
	return listeners, available
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

func TestTenantCertificateOwnershipTracksLiveLease(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "tenant")
	record, _, _, err := registry.Register(types.RegisterChallengeRequest{Namespace: types.LocalTLSNamespaceV1, Identity: owner}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	names, err := registry.tenantCertificateNames(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != record.CanonicalHostname {
		t.Fatalf("issued names = %v", names)
	}
	registry.mu.Lock()
	record.ExpiresAt = time.Now().Add(-time.Second)
	registry.mu.Unlock()
	if _, err := registry.tenantCertificateNames(record); err == nil {
		t.Fatal("expired lease can issue")
	}
	replacement, _, _, err := registry.Register(types.RegisterChallengeRequest{Namespace: types.LocalTLSNamespaceV1, Identity: owner}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.tenantCertificateNames(record); err == nil {
		t.Fatal("replaced lease can issue")
	}
	if _, err := registry.tenantCertificateNames(replacement); err != nil {
		t.Fatal(err)
	}
	registry.setIdentityAccess(owner.ServiceKey(), types.LeaseDenied, 2)
	if _, err := registry.tenantCertificateNames(replacement); err == nil {
		t.Fatal("denied identity can issue")
	}
}

func TestTenantCertificateEndpointRequiresOptInAndAuthentication(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, acmeManager: manager, cfg: utils.NewSnapshot(ServerConfig{})}
	server.identity.Name = "localhost"
	request := func(token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, types.PathV1TenantCertificate, strings.NewReader(body))
		req.Header.Set(types.HeaderAccessToken, token)
		response := httptest.NewRecorder()
		server.HandleTenantCertificate(response, req, nil)
		return response
	}
	if got := request("", "{}"); got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), types.APIErrorCodeTenantIssuanceDisabled) {
		t.Fatalf("disabled status=%d body=%s", got.Code, got.Body.String())
	}
	server.cfg.Swap(ServerConfig{TenantCertificates: true})
	if got := request("", "{}").Code; got != http.StatusForbidden {
		t.Fatalf("unauthenticated status=%d", got)
	}
	_, _, registration, err := registry.Register(types.RegisterChallengeRequest{Namespace: types.LocalTLSNamespaceV1, Identity: newTestLeaseIdentity(t, "tenant")}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(registration.AccessToken, "{}").Code; got != http.StatusBadRequest {
		t.Fatalf("invalid CSR status=%d", got)
	}
}

func TestTenantCertificateRejectsReassignableAlias(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, acmeManager: manager, cfg: utils.NewSnapshot(ServerConfig{TenantCertificates: true})}
	server.identity.Name = "localhost"
	_, _, registration, err := registry.Register(types.RegisterChallengeRequest{Namespace: types.LocalTLSNamespaceV1, Identity: newTestLeaseIdentity(t, "alias")}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{registration.Hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(types.TenantCertificateRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, types.PathV1TenantCertificate, strings.NewReader(string(body)))
	req.Header.Set(types.HeaderAccessToken, registration.AccessToken)
	response := httptest.NewRecorder()
	server.HandleTenantCertificate(response, req, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("alias CSR status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPublicTenantCertificateRequiresExplicitApproval(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	manager, err := acme.NewManager(acme.Config{BaseDomain: "localhost", KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, acmeManager: manager, cfg: utils.NewSnapshot(ServerConfig{TenantCertificates: true})}
	server.identity.Name = "example.com"
	for i := range 3 {
		owner := newTestLeaseIdentity(t, fmt.Sprintf("tenant%d", i))
		_, _, registration, err := registry.Register(types.RegisterChallengeRequest{Namespace: types.LocalTLSNamespaceV1, Identity: owner}, netip.MustParseAddr("203.0.113.1"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		request := func(approved []types.ServiceIdentityKey) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, types.PathV1TenantCertificate, strings.NewReader("{}"))
			req.Header.Set(types.HeaderAccessToken, registration.AccessToken)
			response := httptest.NewRecorder()
			server.HandleTenantCertificate(response, req, approved)
			return response
		}
		if got := request(nil); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), types.APIErrorCodeTenantIssuanceNotApproved) {
			t.Fatalf("issuance approval refusal = %d %s", got.Code, got.Body.String())
		}
		if got := request([]types.ServiceIdentityKey{owner.ServiceKey()}); got.Code != http.StatusBadRequest {
			t.Fatalf("explicit grant did not reach CSR validation: %d", got.Code)
		}
	}
}
