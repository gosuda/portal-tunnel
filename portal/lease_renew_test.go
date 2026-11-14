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
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

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
