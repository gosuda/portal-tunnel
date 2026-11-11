package portal

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNegotiatedNamespaceSeparatesServicesAndLegacyCache(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	var err error
	registry.cache, err = cache.New(cache.Config{Enabled: true, MaxBytes: 1024, MaxTTL: time.Hour}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	register := func(id types.Identity, namespace string) (*leaseRecord, types.RegisterResponse) {
		t.Helper()
		record, _, response, err := registry.Register(types.RegisterChallengeRequest{Identity: id, Namespace: namespace, Cache: true}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return record, response
	}
	owner := newTestLeaseIdentity(t, "blog")
	legacy, old := register(owner, "")
	if old.Namespace != "" || old.LegacyCanonicalHostname != "" {
		t.Fatal("legacy client negotiated implicitly")
	}
	if _, err := registry.tenantCertificateNames(legacy); err == nil {
		t.Fatal("legacy lease authorized local TLS issuance")
	}
	first, current := register(owner, types.LocalTLSNamespaceV1)
	if current.LegacyCanonicalHostname != old.CanonicalHostname || current.CanonicalHostname == old.CanonicalHostname {
		t.Fatal("legacy URL lost or canonical unchanged")
	}
	if first.cacheLeaseLocked().Hostname != old.CanonicalHostname || !registry.cache.Eligible(first.id) {
		t.Fatal("legacy cache migration changed hostname or opt-in")
	}
	sibling := owner
	sibling.Name = "api"
	second, other := register(sibling, types.LocalTLSNamespaceV1)
	if first.id == second.id || current.CanonicalHostname == other.CanonicalHostname {
		t.Fatal("sibling services collided")
	}
	for _, pair := range []struct {
		host   string
		record *leaseRecord
	}{{current.CanonicalHostname, first}, {current.LegacyCanonicalHostname, first}, {other.CanonicalHostname, second}} {
		got, ok := registry.Lookup(pair.host)
		if !ok || got != pair.record {
			t.Fatalf("wrong routing for %q", pair.host)
		}
	}
	stranger := newTestLeaseIdentity(t, "blog")
	_, occupied := register(stranger, types.LocalTLSNamespaceV1)
	if occupied.Hostname != "" || occupied.CanonicalHostname == current.CanonicalHostname {
		t.Fatal("canonical depended on friendly alias")
	}
	server := &Server{registry: registry}
	response := httptest.NewRecorder()
	server.serveCachedSite(response, httptest.NewRequest(http.MethodGet, "https://"+current.CanonicalHostname, nil), current.CanonicalHostname)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("canonical cache response %d", response.Code)
	}
}

func TestNamespaceNegotiationRejectsUnknownAndReservedNames(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "default")
	for _, namespace := range []string{types.LocalTLSNamespaceV1, "unknown-future-namespace"} {
		if _, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: namespace}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil); err == nil {
			t.Fatalf("accepted reserved/unknown namespace %q", namespace)
		}
	}
	if _, _, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil); err != nil {
		t.Fatal("broke legacy default service", err)
	}
	owner.Name = ""
	record, _, response, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: types.LocalTLSNamespaceV1}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "" || response.Hostname != "" {
		t.Fatal("unnamed service acquired a named identity or friendly alias")
	}
	if _, err := registry.tenantCertificateNames(record); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceReplacementDNSOwnership(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	owner := newTestLeaseIdentity(t, "blog")
	register := func(namespace string) (*leaseRecord, *leaseRecord) {
		t.Helper()
		record, replaced, _, err := registry.Register(types.RegisterChallengeRequest{Identity: owner, Namespace: namespace}, netip.MustParseAddr("203.0.113.10"), "", types.RelayDescriptor{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return record, replaced
	}
	original, _ := register(types.LocalTLSNamespaceV1)
	replacement, replaced := register(types.LocalTLSNamespaceV1)
	if replaced != original {
		t.Fatal("registration lost replaced DNS owner")
	}
	server := &Server{registry: registry}
	registry.mu.RLock()
	retained := server.isDNSHostnameOwnedLocked(original.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if !retained {
		t.Fatal("same-namespace replacement would delete live DNS")
	}
	legacy, replaced := register("")
	if replaced != replacement {
		t.Fatal("downgrade lost retired canonical DNS owner")
	}
	registry.mu.RLock()
	stale := server.isDNSHostnameOwnedLocked(replaced.CanonicalHostname, time.Now())
	retained = server.isDNSHostnameOwnedLocked(legacy.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if stale || !retained {
		t.Fatal("downgrade did not isolate retired DNS from legacy live DNS")
	}
	// A newer concurrent registration reclaims the hostname before cleanup.
	newest, _ := register(types.LocalTLSNamespaceV1)
	registry.mu.RLock()
	retained = server.isDNSHostnameOwnedLocked(replaced.CanonicalHostname, time.Now())
	registry.mu.RUnlock()
	if !retained || newest.CanonicalHostname != replaced.CanonicalHostname {
		t.Fatal("late cleanup could delete a reclaimed canonical hostname")
	}
}
