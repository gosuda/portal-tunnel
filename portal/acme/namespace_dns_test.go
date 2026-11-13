package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errTestNamespaceDeletionUnavailable    = errors.New("address deletion unavailable")
	errTestNamespacePublicationUnavailable = errors.New("parent address publication unavailable")
)

func TestCanonicalDNSLifecycleWithoutENS(t *testing.T) {
	const root = "relay.delegated.example.com"
	address := "0x" + strings.Repeat("a", 40)
	parent, _ := utils.CanonicalLeaseHostname("", address, root)
	first, _ := utils.LocalTLSLeaseHostname("", address, root)
	second, _ := utils.LocalTLSLeaseHostname("api", address, root)
	zone := newFakeZone()
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx := t.Context()
	for _, host := range []string{first, second} {
		if err := manager.SyncLeaseHostname(ctx, host, address); err != nil {
			t.Fatal(err)
		}
		command := <-manager.ensCommands
		if err := manager.applyENSCommand(ctx, command); err != nil {
			t.Fatal(err)
		}
		if !zone.hasARecord(parent) || len(zone.txtValues(parent)) != 0 || !zone.hasARecord(host) || len(zone.txtValues(host)) != 0 {
			t.Fatalf("address-only DNS missing or ENS enabled for %s", host)
		}
	}
	tracked, err := manager.trackedENSGaslessHostnames()
	if err != nil || !slices.Contains(tracked, parent) || !slices.Contains(tracked, first) || !slices.Contains(tracked, second) {
		t.Fatalf("tracking: %v %v", tracked, err)
	}
	state := &maintenanceLoopState{lastPublicIPs: map[bool]string{}}
	if err := manager.syncChangedAddressRecords(ctx, state, []string{"203.0.113.11"}); err != nil {
		t.Fatal(err)
	}
	if zone.a[parent] != "203.0.113.11" || zone.a[first] != "203.0.113.11" || zone.a[second] != "203.0.113.11" {
		t.Fatal("canonical addresses not refreshed with ENS disabled")
	}
	if err := zone.EnsureTXTRecord(ctx, second, "unrelated TXT"); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteLeaseHostname(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyENSCommand(ctx, <-manager.ensCommands); err != nil {
		t.Fatal(err)
	}
	if zone.hasARecord(first) || !zone.hasARecord(parent) || !zone.hasARecord(second) || len(zone.txtValues(second)) != 1 {
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
}

type failingNamespaceDNSZone struct {
	*fakeZone
	unavailableChild string
}

func (z *failingNamespaceDNSZone) DeleteAddressRecords(ctx context.Context, name string) error {
	if name == z.unavailableChild {
		return errTestNamespaceDeletionUnavailable
	}
	return z.fakeZone.DeleteAddressRecords(ctx, name)
}

func TestNamespaceDNSRetainsParentUntilChildWithdrawn(t *testing.T) {
	const root = "relay.delegated.example.com"
	address := "0x" + strings.Repeat("a", 40)
	parent, _ := utils.CanonicalLeaseHostname("", address, root)
	child, _ := utils.LocalTLSLeaseHostname("api", address, root)
	zone := &failingNamespaceDNSZone{fakeZone: newFakeZone(), unavailableChild: child}
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx := t.Context()
	if err := manager.SyncLeaseHostname(ctx, child, address); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyENSCommand(ctx, <-manager.ensCommands); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{child, parent} {
		if err := manager.DeleteLeaseHostname(ctx, name); err != nil {
			t.Fatal(err)
		}
		if err := manager.applyENSCommand(ctx, <-manager.ensCommands); err == nil {
			t.Fatalf("cleanup must remain pending for %s", name)
		}
	}
	restarted := newTestENSManager(manager.cfg, zone)
	if err := restarted.reconcileTrackedENSGaslessHostnames(ctx); err == nil {
		t.Fatal("expected failed child withdrawal after restart")
	}
	if !zone.hasARecord(parent) || !zone.hasARecord(child) {
		t.Fatal("withdrawing the parent would strand the legacy address")
	}
	zone.unavailableChild = ""
	if err := restarted.reconcileTrackedENSGaslessHostnames(ctx); err != nil {
		t.Fatal(err)
	}
	if zone.hasARecord(parent) || zone.hasARecord(child) {
		t.Fatal("successful reconciliation did not withdraw both owners")
	}
}

func TestNamespaceDNSLeavesUntrackedLegacyAddressAlone(t *testing.T) {
	const root = "relay.delegated.example.com"
	address := "0x" + strings.Repeat("a", 40)
	parent, _ := utils.CanonicalLeaseHostname("", address, root)
	zone := newFakeZone()
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	ctx := t.Context()
	if err := zone.EnsureAddressRecord(ctx, parent, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SyncLeaseHostname(ctx, parent, address); err != nil || len(manager.ensCommands) != 0 {
		t.Fatalf("legacy-only registration must keep existing wildcard behavior: %v", err)
	}
	if err := manager.DeleteLeaseHostname(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyENSCommand(ctx, <-manager.ensCommands); err != nil {
		t.Fatal(err)
	}
	if !zone.hasARecord(parent) {
		t.Fatal("legacy cleanup removed an untracked address")
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
	parent, _ := utils.CanonicalLeaseHostname("", address, root)
	child, _ := utils.LocalTLSLeaseHostname("api", address, root)
	zone := &namespaceDNSPublicationZone{fakeZone: newFakeZone(), unavailableParent: parent}
	manager := newTestENSManager(Config{BaseDomain: root, KeyDir: t.TempDir()}, zone)
	state := &maintenanceLoopState{pendingENS: make(map[string]ensDNSCommand)}
	previous := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = &http.Client{Transport: publicIPTransport{ip: "203.0.113.10"}}
	t.Cleanup(func() { utils.DefaultHTTPClient = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := manager.SyncLeaseHostname(ctx, child, address); err != nil {
		t.Fatal(err)
	}
	manager.maintenanceLoopHandleENSCommand(ctx, state, <-manager.ensCommands)
	if zone.hasARecord(child) {
		t.Fatal("canonical DNS must not be published before the parent")
	}
	// Model successful prior addresses but a failed refresh. Durable intent
	// alone must not admit a new DNS-01 order while publication is pending.
	if err := manager.updateTrackedENSGaslessHostnames(func([]string) []string { return []string{parent, child} }); err != nil {
		t.Fatal(err)
	}
	encoded, _ := tenantCSR(t, &x509.CertificateRequest{DNSNames: []string{child}})
	csr, err := ParseTenantCSR(encoded, []string{child})
	if err != nil {
		t.Fatal(err)
	}
	issued := make(chan error, 1)
	go func() {
		_, err := manager.ObtainTenantCertificate(ctx, csr)
		issued <- err
	}()
	select {
	case command := <-manager.ensCommands:
		manager.maintenanceLoopHandleENSCommand(ctx, state, command)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-issued; !errors.Is(err, errLeaseDNSPending) {
		t.Fatalf("failed address publication reached issuance admission: %v", err)
	}
	zone.unavailableParent = ""
	// An old last-child removal may still be queued when a new sibling
	// acquires the same parent. The successful retry supersedes it.
	state.pendingENS[parent] = ensDNSCommand{hostname: parent, remove: true}
	_ = manager.maintenanceLoopApplyPendingENS(ctx, state)
	if !zone.hasARecord(parent) || !zone.hasARecord(child) {
		t.Fatal("retry did not publish both exact addresses")
	}
	if err := manager.checkLeaseDNS(state, child); err != nil {
		t.Fatalf("successful address publication still blocks issuance: %v", err)
	}
}
