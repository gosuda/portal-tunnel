package acme

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type fakeZone struct {
	mu  sync.Mutex
	txt map[string][]string
	a   map[string]string
}

func newFakeZone() *fakeZone {
	return &fakeZone{txt: map[string][]string{}, a: map[string]string{}}
}

func (z *fakeZone) txtValues(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[name]...)
}

func (z *fakeZone) hasARecord(name string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	_, ok := z.a[name]
	return ok
}

func (z *fakeZone) Name() string { return TypeEmbedded }

func (z *fakeZone) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return nil, nil
}

func (z *fakeZone) EnsureAddressRecords(_ context.Context, baseDomain, publicIP string) error {
	return z.EnsureAddressRecord(context.Background(), baseDomain, publicIP)
}

func (z *fakeZone) EnsureAddressRecord(_ context.Context, name, publicIP string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.a[name] = publicIP
	return nil
}

func (z *fakeZone) DeleteAddressRecords(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.a, name)
	return nil
}

func (z *fakeZone) EnsureTXTRecord(_ context.Context, name, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if slices.Contains(z.txt[name], value) {
		return nil
	}
	z.txt[name] = append(z.txt[name], value)
	return nil
}

func (z *fakeZone) DeleteTXTRecords(_ context.Context, name, matchPrefix string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	kept := z.txt[name][:0]
	for _, value := range z.txt[name] {
		if !strings.HasPrefix(value, matchPrefix) {
			kept = append(kept, value)
		}
	}
	if len(kept) == 0 {
		delete(z.txt, name)
		return nil
	}
	z.txt[name] = kept
	return nil
}

func (z *fakeZone) EnsureDNSSEC(context.Context, string) (string, string, string, error) {
	return "", "", "", nil
}

func newTestENSManager(cfg Config, dns dnsProvider) *Manager {
	cfg.BaseDomain = types.NormalizeBaseDomain(cfg.BaseDomain)
	return &Manager{
		cfg:         cfg,
		dns:         dns,
		stopCh:      make(chan struct{}),
		ensCommands: make(chan ensDNSCommand, 1),
		ensStatus:   utils.NewSnapshot(newENSStatus(cfg, dns)),
	}
}

type failingTXTZone struct {
	dnsProvider
	err error
}

func (z failingTXTZone) DeleteTXTRecords(context.Context, string, string) error {
	return z.err
}

func ensTXTValues(t *testing.T, zone *fakeZone, name string) []string {
	t.Helper()
	var ens []string
	for _, value := range zone.txtValues(name) {
		if strings.HasPrefix(value, gaslessENSTXTPrefix) {
			ens = append(ens, value)
		}
	}
	return ens
}

func TestENSGaslessAddressChangeLeavesOneRecord(t *testing.T) {
	const host = "portal.example.com"
	const challengeValue = "acme-challenge-token"

	zone := newFakeZone()
	if err := zone.EnsureTXTRecord(context.Background(), host, challengeValue); err != nil {
		t.Fatalf("seed DNS-01 record: %v", err)
	}

	manager := newTestENSManager(Config{
		BaseDomain:        host,
		KeyDir:            t.TempDir(),
		ENSGaslessEnabled: true,
	}, zone)

	first := "0x1111111111111111111111111111111111111111"
	second := "0x2222222222222222222222222222222222222222"
	applyGaslessAddressChange(t, manager, host, first, second)
	checkGaslessAddressSingleRecord(t, zone, host, second, challengeValue)
}

func applyGaslessAddressChange(t *testing.T, manager *Manager, host, first, second string) {
	t.Helper()
	for _, address := range []string{first, second} {
		if err := manager.applyENSCommand(context.Background(), ensDNSCommand{hostname: host, address: address}); err != nil {
			t.Fatalf("applyENSCommand(%s): %v", address, err)
		}
	}
}

func checkGaslessAddressSingleRecord(t *testing.T, zone *fakeZone, host, second, challengeValue string) {
	t.Helper()
	ens := ensTXTValues(t, zone, host)
	if len(ens) != 1 {
		t.Fatalf("ENS1 records = %v, want exactly one", ens)
	}
	if !strings.HasSuffix(ens[0], second) {
		t.Fatalf("ENS1 record = %q, want the current address %s", ens[0], second)
	}
	if !slices.Contains(zone.txtValues(host), challengeValue) {
		t.Fatalf("TXT records = %v, want the DNS-01 record left untouched", zone.txtValues(host))
	}
}
func TestENSGaslessLeaseRemovalDoesNotRunWhenDisabled(t *testing.T) {
	const host = "lease.portal.example.com"

	zone := newFakeZone()
	manager := newTestENSManager(Config{
		BaseDomain:        "portal.example.com",
		KeyDir:            t.TempDir(),
		ENSGaslessEnabled: false,
	}, zone)

	ctx := context.Background()
	if err := zone.EnsureAddressRecord(ctx, host, "203.0.113.10"); err != nil {
		t.Fatalf("seed A record: %v", err)
	}

	if err := manager.DeleteLeaseHostname(ctx, host); err != nil {
		t.Fatalf("DeleteLeaseHostname(): %v", err)
	}
	if !zone.hasARecord(host) {
		t.Fatalf("untracked A record for %s was deleted", host)
	}
}

func TestENSGaslessReconcileRunsWhenDisabled(t *testing.T) {
	const (
		baseDomain = "portal.example.com"
		host       = "lease.portal.example.com"
	)

	keyDir := t.TempDir()
	trackedPath := filepath.Join(keyDir, ensGaslessHostnamesFileName)
	ctx := context.Background()
	zone := newFakeZone()
	seedDisabledReconcileZone(t, zone, baseDomain, host, trackedPath)

	manager := newTestENSManager(Config{
		BaseDomain:        baseDomain,
		KeyDir:            keyDir,
		ENSGaslessEnabled: false,
		ENSGaslessAddress: "0x3333333333333333333333333333333333333333",
	}, zone)

	if err := manager.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		t.Fatalf("reconcileTrackedENSGaslessHostnames(): %v", err)
	}
	checkDisabledReconcileWithdrawn(t, zone, baseDomain, host, trackedPath)
}

func TestENSGaslessReconcileReportsTXTWithdrawalFailure(t *testing.T) {
	const (
		baseDomain = "portal.example.com"
		host       = "lease.portal.example.com"
	)
	keyDir := t.TempDir()
	trackedPath := filepath.Join(keyDir, ensGaslessHostnamesFileName)
	if err := utils.WriteJSONFile(trackedPath, []string{host}, 0o600); err != nil {
		t.Fatalf("seed tracked hostnames: %v", err)
	}
	ctx := context.Background()
	zone := newFakeZone()
	if err := zone.EnsureTXTRecord(ctx, host, gaslessENSTXTPrefix+"resolver 0x4444"); err != nil {
		t.Fatalf("seed ENS record: %v", err)
	}
	if err := zone.EnsureAddressRecord(ctx, host, "203.0.113.11"); err != nil {
		t.Fatalf("seed A record: %v", err)
	}
	txtErr := errors.New("txt withdrawal unavailable")
	manager := newTestENSManager(Config{BaseDomain: baseDomain, KeyDir: keyDir}, failingTXTZone{dnsProvider: zone, err: txtErr})
	if err := manager.reconcileTrackedENSGaslessHostnames(ctx); !errors.Is(err, txtErr) {
		t.Fatalf("reconcileTrackedENSGaslessHostnames() = %v, want the txt withdrawal failure", err)
	}
	if !zone.hasARecord(host) {
		t.Fatal("address record was deleted after the txt withdrawal failed")
	}
}

func seedDisabledReconcileZone(t *testing.T, zone *fakeZone, baseDomain, host, trackedPath string) {
	t.Helper()
	if err := utils.WriteJSONFile(trackedPath, []string{host}, 0o600); err != nil {
		t.Fatalf("seed tracked hostnames: %v", err)
	}
	ctx := context.Background()
	if err := zone.EnsureTXTRecord(ctx, baseDomain, gaslessENSTXTPrefix+"resolver 0x3333"); err != nil {
		t.Fatalf("seed base ENS record: %v", err)
	}
	if err := zone.EnsureTXTRecord(ctx, host, gaslessENSTXTPrefix+"resolver 0x4444"); err != nil {
		t.Fatalf("seed ENS record: %v", err)
	}
	if err := zone.EnsureAddressRecord(ctx, host, "203.0.113.11"); err != nil {
		t.Fatalf("seed A record: %v", err)
	}
}

func checkDisabledReconcileWithdrawn(t *testing.T, zone *fakeZone, baseDomain, host, trackedPath string) {
	t.Helper()
	if ens := ensTXTValues(t, zone, baseDomain); len(ens) != 0 {
		t.Fatalf("base ENS1 records = %v, want them withdrawn", ens)
	}
	if ens := ensTXTValues(t, zone, host); len(ens) != 0 {
		t.Fatalf("ENS1 records = %v, want them withdrawn", ens)
	}
	if zone.hasARecord(host) {
		t.Fatalf("A record for %s survived the reconcile", host)
	}
	if _, err := os.Stat(trackedPath); !os.IsNotExist(err) {
		t.Fatalf("tracked hostnames file still present (stat err = %v), want it cleared", err)
	}
}

var (
	errTestNamespacePublicationUnavailable = errors.New("service address publication unavailable")
)

func TestCanonicalDNSLifecycle(t *testing.T) {
	for name, ens := range map[string]bool{"without ENS": false, "with ENS": true} {
		t.Run(name, func(t *testing.T) {
			const root = "relay.delegated.example.com"
			address := "0x" + strings.Repeat("a", 40)
			parent := strings.TrimPrefix(address, "0x") + "." + root
			first, _ := namespace.LocalTLSHostname("", address, root)
			second, _ := namespace.LocalTLSHostname("api", address, root)
			zone := newFakeZone()
			manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir(), ENSGaslessEnabled: ens}, zone)
			previous := utils.DefaultHTTPClient
			utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
			t.Cleanup(func() { utils.DefaultHTTPClient = previous })
			ctx := t.Context()
			wantTXT := 0
			if ens {
				wantTXT = 1
			}
			state := &maintenanceLoopState{lastPublicIPs: map[bool]string{}}
			for _, host := range []string{first, second} {
				if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
					t.Fatal(err)
				}
				if err := manager.maintenanceLoopApplyPendingENS(ctx, state); err != nil {
					t.Fatal(err)
				}
				if zone.hasARecord(parent) || len(zone.txtValues(parent)) != 0 || !zone.hasARecord(host) || len(zone.txtValues(host)) != wantTXT {
					t.Fatalf("namespace DNS or ENS TXT missing for %s", host)
				}
			}
			tracked, err := manager.trackedENSGaslessHostnames()
			if err != nil || slices.Contains(tracked, parent) || !slices.Contains(tracked, first) || !slices.Contains(tracked, second) {
				t.Fatalf("tracking: %v %v", tracked, err)
			}
			if err := manager.syncChangedAddressRecords(ctx, state, []string{"203.0.113.11"}); err != nil {
				t.Fatal(err)
			}
			if zone.a[first] != "203.0.113.11" || zone.a[second] != "203.0.113.11" {
				t.Fatal("canonical addresses not refreshed")
			}
			if err := zone.EnsureTXTRecord(ctx, second, "unrelated TXT"); err != nil {
				t.Fatal(err)
			}
			if err := manager.DeleteLeaseHostname(ctx, first); err != nil {
				t.Fatal(err)
			}
			if err := manager.maintenanceLoopApplyPendingENS(ctx, state); err != nil {
				t.Fatal(err)
			}
			if zone.hasARecord(first) || zone.hasARecord(parent) || !zone.hasARecord(second) || len(zone.txtValues(second)) != wantTXT+1 {
				t.Fatal("removal crossed sibling service boundary")
			}
			restarted := newTestENSManager(manager.cfg, zone)
			if err := restarted.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
				t.Fatal(err)
			}
			if zone.hasARecord(second) || zone.hasARecord(parent) {
				t.Fatal("restart did not withdraw stale lease address")
			}
			if len(zone.txtValues(second)) != 1 {
				t.Fatal("restart removed unrelated TXT")
			}
		})
	}
}

type namespaceDNSPublicationZone struct {
	*fakeZone
	unavailableParent string
}

func (z *namespaceDNSPublicationZone) Name() string { return TypeCloudflare }

func (z *namespaceDNSPublicationZone) EnsureAddressRecord(ctx context.Context, name, ip string) error {
	if name == z.unavailableParent {
		return errTestNamespacePublicationUnavailable
	}
	return z.fakeZone.EnsureAddressRecord(ctx, name, ip)
}

func TestTenantIssuanceWaitsForNamespaceAddressDNS(t *testing.T) {
	const root = "relay.delegated.example.com"
	address := "0x" + strings.Repeat("a", 40)
	child, _ := namespace.LocalTLSHostname("api", address, root)
	zone := &namespaceDNSPublicationZone{fakeZone: newFakeZone(), unavailableParent: child}
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	state := &maintenanceLoopState{}
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	if err := manager.SyncLeaseHostname(t.Context(), child, address); err != nil {
		t.Fatal(err)
	}
	manager.maintenanceLoopHandleENSCommand(t.Context(), state, <-manager.ensCommands)
	if zone.hasARecord(child) {
		t.Fatal("failed DNS publication became visible")
	}
	if err := manager.checkLeaseDNS(child); !errors.Is(err, errLeaseDNSPending) {
		t.Fatalf("failed publication admitted issuance: %v", err)
	}
	zone.unavailableParent = ""
	_ = manager.maintenanceLoopApplyPendingENS(t.Context(), state)
	if !zone.hasARecord(child) {
		t.Fatal("retry did not publish exact service DNS")
	}
	if err := manager.checkLeaseDNS(child); err != nil {
		t.Fatal(err)
	}
}

type pausedDNSRemovalZone struct {
	*fakeZone
	started chan struct{}
	resume  chan struct{}
}

func TestLeaseDNSReadinessWaitsForPublication(t *testing.T) {
	const root = "relay.example.com"
	address := "0x" + strings.Repeat("a", 40)
	host, _ := namespace.LocalTLSHostname("api", address, root)
	zone := &namespaceDNSPublicationZone{fakeZone: newFakeZone()}
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	manager.Start(ctx)
	defer func() { cancel(); _ = manager.Stop(t.Context()) }()
	if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
		t.Fatal(err)
	}
	if err := manager.waitLeaseDNS(ctx, host); err != nil {
		t.Fatal(err)
	}
	if !zone.hasARecord(host) {
		t.Fatal("DNS-01 admitted before address publication")
	}
}

func (z *pausedDNSRemovalZone) DeleteAddressRecords(ctx context.Context, name string) error {
	select {
	case z.started <- struct{}{}:
	default:
	}
	select {
	case <-z.resume:
		return z.fakeZone.DeleteAddressRecords(ctx, name)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestLeaseDNSChangesDoNotWaitForProviderAndKeepNewestOwner(t *testing.T) {
	const root = "relay.example.com"
	address := "0x" + strings.Repeat("a", 40)
	host, _ := namespace.LocalTLSHostname("api", address, root)
	zone := &pausedDNSRemovalZone{fakeZone: newFakeZone(), started: make(chan struct{}, 1), resume: make(chan struct{})}
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := zone.EnsureAddressRecord(ctx, host, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteLeaseHostname(ctx, host); err != nil {
		t.Fatal(err)
	}
	state := &maintenanceLoopState{}
	done := make(chan struct{})
	go func() {
		manager.maintenanceLoopHandleENSCommand(ctx, state, <-manager.ensCommands)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-zone.started:
	case <-ctx.Done():
		t.Fatal("DNS removal did not reach provider")
	}
	// Repeated policy/registration changes must be accepted while the sole
	// worker is in provider I/O. Only the final desired state needs applying.
	for range 512 {
		if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
			t.Fatal("registration waited for DNS provider:", err)
		}
		if err := manager.DeleteLeaseHostname(ctx, host); err != nil {
			t.Fatal("withdrawal waited for DNS provider:", err)
		}
	}
	if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
		t.Fatal(err)
	}
	close(zone.resume)
	<-done
	if err := manager.maintenanceLoopApplyPendingENS(ctx, state); err != nil {
		t.Fatal(err)
	}
	if !zone.hasARecord(host) {
		t.Fatal("old withdrawal discarded the new registration")
	}
	if err := manager.checkLeaseDNS(host); err != nil {
		t.Fatal("new registration did not become ready:", err)
	}
}

func TestLeaseDNSFailedWithdrawalIsSupersededByRegistration(t *testing.T) {
	const root = "relay.example.com"
	address := "0x" + strings.Repeat("a", 40)
	host, _ := namespace.LocalTLSHostname("api", address, root)
	zone := newFakeZone()
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, failingTXTZone{dnsProvider: zone, err: errTestNamespacePublicationUnavailable})
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	state := &maintenanceLoopState{}
	if err := manager.DeleteLeaseHostname(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	if err := manager.maintenanceLoopApplyPendingENS(t.Context(), state); !errors.Is(err, errTestNamespacePublicationUnavailable) {
		t.Fatalf("failed withdrawal: %v", err)
	}
	if err := manager.checkLeaseDNS(host); !errors.Is(err, errLeaseDNSPending) {
		t.Fatalf("failed work was not retained: %v", err)
	}
	if err := manager.SyncLeaseHostname(t.Context(), host, address); err != nil {
		t.Fatal(err)
	}
	if err := manager.maintenanceLoopApplyPendingENS(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	if !zone.hasARecord(host) {
		t.Fatal("failed withdrawal outlived a new registration")
	}
	if err := manager.checkLeaseDNS(host); err != nil {
		t.Fatal(err)
	}
}
