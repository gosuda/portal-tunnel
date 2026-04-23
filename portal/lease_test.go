package portal

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newTestRegistry(t *testing.T) *leaseRegistry {
	t.Helper()
	registry, err := newLeaseRegistry(false, false, false, "")
	if err != nil {
		t.Fatalf("newLeaseRegistry() error = %v", err)
	}
	return registry
}

func TestLeaseRegistryLifecycle(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t)
	runtime := registry.policy
	record := &leaseRecord{
		Identity: types.Identity{
			Name:    "demo",
			Address: "addr-1",
		},
		Hostname:  "demo.example.com",
		ExpiresAt: time.Now().Add(30 * time.Second),
		stream:    transport.NewRelayStream("addr-1", time.Minute, 1),
	}

	if err := registry.Register(record); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	lookedUp, ok := registry.Lookup("demo.example.com")
	if !ok || lookedUp != record {
		t.Fatalf("Lookup() = %v, %v, want registered lease", lookedUp, ok)
	}

	renewed, err := registry.Renew(record.Key(), time.Minute, "203.0.113.10", utils.PublicIPs{})
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if renewed.ClientIP != "203.0.113.10" {
		t.Fatalf("Renew() client ip = %q, want %q", renewed.ClientIP, "203.0.113.10")
	}
	if got := runtime.IPFilter().IdentityIP(record.Key()); got != "203.0.113.10" {
		t.Fatalf("Renew() did not register client IP for lease")
	}

	removed, err := registry.Unregister(record.Key())
	if err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
	if removed != record {
		t.Fatalf("Unregister() record = %v, want original record", removed)
	}

	if _, ok := registry.Lookup("demo.example.com"); ok {
		t.Fatal("Lookup() after Unregister() = true, want false")
	}
	if got := runtime.IPFilter().IdentityIP(record.Key()); got != "" {
		t.Fatalf("Unregister() lease IP = %q, want empty", got)
	}
}

func TestLeaseRegistryWildcardAndConflict(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t)
	wildcardLease := &leaseRecord{
		Identity: types.Identity{
			Name:    "wildcard",
			Address: "addr-wildcard",
		},
		Hostname:  "*.example.com",
		ExpiresAt: time.Now().Add(30 * time.Second),
		stream:    transport.NewRelayStream("addr-wildcard", time.Minute, 1),
	}
	if err := registry.Register(wildcardLease); err != nil {
		t.Fatalf("Register(wildcard) error = %v", err)
	}

	if _, ok := registry.Lookup("app.example.com"); !ok {
		t.Fatal("Lookup(one-level wildcard) = false, want true")
	}
	if _, ok := registry.Lookup("deep.app.example.com"); ok {
		t.Fatal("Lookup(multi-level wildcard) = true, want false")
	}

	conflict := &leaseRecord{
		Identity: types.Identity{
			Name:    "conflict",
			Address: "addr-conflict",
		},
		Hostname:  "*.example.com",
		ExpiresAt: time.Now().Add(30 * time.Second),
		stream:    transport.NewRelayStream("addr-conflict", time.Minute, 1),
	}
	err := registry.Register(conflict)
	if !errors.Is(err, errHostnameConflict) {
		t.Fatalf("Register(conflict) error = %v, want hostname conflict", err)
	}
}

func TestLeaseRegistryAdminLeasesAndRoutableUsePolicy(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t)
	runtime := registry.policy
	if err := runtime.Approver().SetMode(policy.ModeManual); err != nil {
		t.Fatalf("SetMode() error = %v", err)
	}
	record := &leaseRecord{
		Identity: types.Identity{
			Name:    "demo",
			Address: "addr-policy",
		},
		Hostname:  "demo.example.com",
		ExpiresAt: time.Now().Add(30 * time.Second),
		ClientIP:  "203.0.113.20",
		stream:    transport.NewRelayStream("addr-policy", time.Minute, 1),
	}
	if err := registry.Register(record); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if registry.policy.IsIdentityRoutable(record.Key()) {
		t.Fatal("policy.IsIdentityRoutable() = true, want false before approval")
	}

	leases := registry.AdminLeases(time.Now())
	if len(leases) != 1 {
		t.Fatalf("AdminLeases() length = %d, want 1", len(leases))
	}
	if leases[0].IsApproved {
		t.Fatal("AdminLeases()[0].IsApproved = true, want false before approval")
	}
	if got := runtime.IPFilter().IdentityIP(record.Key()); got != "203.0.113.20" {
		t.Fatalf("Register() lease IP = %q, want %q", got, "203.0.113.20")
	}

	runtime.Approver().Approve(record.Key())
	if !registry.policy.IsIdentityRoutable(record.Key()) {
		t.Fatal("policy.IsIdentityRoutable() = false, want true after approval")
	}

	leases = registry.AdminLeases(time.Now())
	if len(leases) != 1 {
		t.Fatalf("AdminLeases() length = %d, want 1", len(leases))
	}
	if !leases[0].IsApproved {
		t.Fatal("AdminLeases()[0].IsApproved = false, want true after approval")
	}
}

func TestLeaseRegistryPublicLeasesIncludesIngressRouteInManualApproval(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t)
	if err := registry.policy.Approver().SetMode(policy.ModeManual); err != nil {
		t.Fatalf("SetMode() error = %v", err)
	}
	route := &leaseRecord{
		Identity: types.Identity{
			Name:    "demo",
			Address: "addr-ingress",
		},
		Hostname:  "demo.example.com",
		ExpiresAt: time.Now().Add(30 * time.Second),
	}
	if err := registry.Register(route); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	leases := registry.PublicLeases(time.Now())
	if len(leases) != 1 {
		t.Fatalf("PublicLeases() length = %d, want 1", len(leases))
	}
	if leases[0].Hostname != route.Hostname {
		t.Fatalf("PublicLeases()[0].Hostname = %q, want %q", leases[0].Hostname, route.Hostname)
	}
}

func TestLeaseRegistryCleanupExpiredClosesBroker(t *testing.T) {
	t.Parallel()

	registry := newTestRegistry(t)
	record := &leaseRecord{
		Identity: types.Identity{
			Name:    "expired",
			Address: "addr-expired",
		},
		Hostname:  "expired.example.com",
		ExpiresAt: time.Now().Add(-time.Second),
		stream:    transport.NewRelayStream("addr-expired", time.Minute, 1),
	}
	if err := registry.Register(record); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	for _, lease := range registry.cleanupExpired(time.Now()) {
		lease.Close()
	}

	if _, ok := registry.Lookup("expired.example.com"); ok {
		t.Fatal("Lookup() after cleanupExpired() = true, want false")
	}
	if _, err := record.stream.Claim(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Claim() after cleanupExpired() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestServerRunRegistryJanitorRejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()

	server := &Server{registry: newTestRegistry(t)}
	err := server.runRegistryJanitor(context.Background(), 0)
	if err == nil {
		t.Fatal("runRegistryJanitor() error = nil, want validation error")
	}
}
