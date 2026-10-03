package portal

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestNameReservationSurvivesLeaseLifecycle(t *testing.T) {
	t.Parallel()
	for _, offline := range []string{"unregister", "expiry", "restart"} {
		t.Run(offline, func(t *testing.T) {
			registry := newTestRegistry(t, false, false)
			alice := newTestLeaseIdentity(t, "stable")
			_, response, err := registry.Register(
				types.RegisterChallengeRequest{Identity: alice, Metadata: types.LeaseMetadata{Hide: true}},
				"203.0.113.1", "", types.RelayDescriptor{}, nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			switch offline {
			case "unregister":
				if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: response.AccessToken}); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				registry.cleanupExpired(response.ExpiresAt)
			case "restart":
				registry.CloseAll()
				restored, err := loadNameReservations(registry.names.path, registry.rootHostname, registry.names.ttl)
				if err != nil {
					t.Fatal(err)
				}
				registry.names = restored
			}
			if _, ok := registry.Lookup("stable.example.com"); ok {
				t.Fatal("offline name must have no route")
			}
			bob := newTestLeaseIdentity(t, "stable")
			if _, _, err := registry.Register(
				types.RegisterChallengeRequest{Identity: bob}, "203.0.113.1", "", types.RelayDescriptor{}, nil,
			); !errors.Is(err, errHostnameConflict) {
				t.Fatalf("different identity, same IP: %v, want hostname_conflict", err)
			}
			if _, _, err := registry.Register(
				types.RegisterChallengeRequest{Identity: alice}, "203.0.113.2", "", types.RelayDescriptor{}, nil,
			); err != nil {
				t.Fatalf("same identity, changed IP: %v", err)
			}
		})
	}
}

func TestNameReservationExpiryAndRefresh(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "names.json")
	store, err := loadNameReservations(path, "example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	alice := &leaseRecord{Identity: newTestLeaseIdentity(t, "stable"), Hostname: "stable.example.com"}
	bob := &leaseRecord{Identity: newTestLeaseIdentity(t, "stable"), Hostname: alice.Hostname}
	if err := store.Reserve(alice, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	firstDeadline := now.Add(time.Minute + time.Hour)
	if err := store.Reserve(bob, firstDeadline, firstDeadline.Add(-time.Nanosecond)); !errors.Is(err, errHostnameConflict) {
		t.Fatalf("early takeover: %v", err)
	}
	if err := store.Reserve(alice, now.Add(2*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	refreshed, err := loadNameReservations(path, "example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := refreshed.Reserve(bob, firstDeadline, firstDeadline); !errors.Is(err, errHostnameConflict) {
		t.Fatalf("renewed reservation lost after restart: %v", err)
	}
	deadline := now.Add(2*time.Minute + time.Hour)
	if err := refreshed.Reserve(bob, deadline.Add(time.Minute), deadline); err != nil {
		t.Fatalf("takeover at expiration: %v", err)
	}
	if err := refreshed.Reserve(alice, deadline.Add(time.Minute), deadline); !errors.Is(err, errHostnameConflict) {
		t.Fatalf("old owner retained ownership after takeover: %v", err)
	}
}

func TestNameReservationRenewalIsDurable(t *testing.T) {
	t.Parallel()
	registry := newTestRegistry(t, false, false)
	_, response, err := registry.Register(
		types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "stable")},
		"203.0.113.1", "", types.RelayDescriptor{}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _, err := registry.Renew(types.RenewRequest{AccessToken: response.AccessToken, TTL: 3600}, "203.0.113.2")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := loadNameReservations(registry.names.path, registry.rootHostname, registry.names.ttl)
	if err != nil {
		t.Fatal(err)
	}
	want := renewed.ExpiresAt.Add(registry.names.ttl)
	if got := restored.entries["stable.example.com"].ReservedUntil; !got.Equal(want) {
		t.Fatalf("persisted deadline = %v, want %v", got, want)
	}
}

func TestNameReservationConcurrentClaims(t *testing.T) {
	t.Parallel()
	registry := newTestRegistry(t, false, false)
	results := make(chan error, 8)
	identities := make([]types.Identity, cap(results))
	for i := range identities {
		identities[i] = newTestLeaseIdentity(t, "stable")
	}
	var group sync.WaitGroup
	for _, claimant := range identities {
		group.Go(func() {
			_, _, err := registry.Register(
				types.RegisterChallengeRequest{Identity: claimant}, "203.0.113.1", "", types.RelayDescriptor{}, nil,
			)
			results <- err
		})
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, errHostnameConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful owners = %d, want 1", winners)
	}
	active, ok := registry.Lookup("stable.example.com")
	if !ok {
		t.Fatal("winner has no route")
	}
	restored, err := loadNameReservations(registry.names.path, registry.rootHostname, registry.names.ttl)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.entries[active.Hostname].Owner; got != active.Key() {
		t.Fatalf("durable owner = %q, active owner = %q", got, active.Key())
	}
}

func TestNameReservationWriteFailureCannotPublishLease(t *testing.T) {
	t.Parallel()
	registry := newTestRegistry(t, false, false)
	if err := os.Mkdir(registry.names.path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := registry.Register(
		types.RegisterChallengeRequest{Identity: newTestLeaseIdentity(t, "stable")},
		"203.0.113.1", "", types.RelayDescriptor{}, nil,
	)
	if err == nil {
		t.Fatal("registration must fail if reservations cannot be persisted")
	}
	api, ok := errors.AsType[*apiError](err)
	if !ok || api.status != http.StatusInternalServerError {
		t.Fatalf("storage failure = %v, want internal server error", err)
	}
	if _, ok := registry.Lookup("stable.example.com"); ok {
		t.Fatal("failed durable write published a route")
	}
}

func TestNameReservationRejectsCorruptState(t *testing.T) {
	t.Parallel()
	for _, data := range []string{"{", "null", `{"stable.example.com":{"owner_identity_key":"wrong","reserved_until":"2030-01-01T00:00:00Z"}}`} {
		path := filepath.Join(t.TempDir(), "name-reservations.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNameReservations(path, "example.com", time.Hour); err == nil {
			t.Fatalf("accepted corrupt state %q", data)
		}
	}
}

func TestNameReservationTTLValidation(t *testing.T) {
	t.Parallel()
	for _, ttl := range []time.Duration{-time.Second, time.Nanosecond, 366 * 24 * time.Hour} {
		if _, err := ValidateServerConfig(ServerConfig{
			PortalURL: "https://example.com", StateDir: t.TempDir(), NameReservationTTL: ttl,
		}); err == nil {
			t.Fatalf("accepted TTL %v", ttl)
		}
	}
	cfg, err := ValidateServerConfig(ServerConfig{PortalURL: "https://example.com", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NameReservationTTL != DefaultNameReservationTTL {
		t.Fatalf("default TTL = %v", cfg.NameReservationTTL)
	}
}
