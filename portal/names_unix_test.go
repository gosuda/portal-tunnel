//go:build !windows

package portal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNameReservationPostRenameFailureProtectsTentativeOwner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, err := loadNameReservations(filepath.Join(dir, "names.json"), "example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	alice := &leaseRecord{Identity: newTestLeaseIdentity(t, "stable"), Hostname: "stable.example.com"}
	bob := &leaseRecord{Identity: newTestLeaseIdentity(t, "stable"), Hostname: alice.Hostname}
	if err := store.Reserve(alice, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	original := store.durable[alice.Hostname]
	now = original.ReservedUntil
	// Write/search allow temporary creation and rename, but read denial makes
	// opening the parent for directory sync fail after ownership replacement.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Close()
		t.Skip("process privileges bypass directory read permissions")
	}
	if err := store.Reserve(bob, now.Add(time.Minute), now); err == nil {
		t.Fatal("post-rename failure acknowledged new ownership")
	}
	if store.writeErr == nil || store.entries[bob.Hostname].Owner != bob.Key() || store.durable[alice.Hostname] != original {
		t.Fatal("uncertain replacement lost tentative or confirmed ownership")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(bob, now.Add(time.Minute), now); err == nil {
		t.Fatal("tentative owner retried through durable fast path")
	}
	if err := store.Reserve(alice, now.Add(time.Minute), now); !errors.Is(err, errHostnameConflict) {
		t.Fatalf("old owner bypassed tentative owner: %v", err)
	}
	restored, err := loadNameReservations(store.path, "example.com", store.ttl)
	if err != nil {
		t.Fatal(err)
	}
	if restored.entries[bob.Hostname].Owner != bob.Key() {
		t.Fatal("restart lost replaced owner")
	}
	if err := restored.Reserve(bob, now.Add(time.Minute), now); err != nil {
		t.Fatalf("repaired storage and restart did not recover: %v", err)
	}
}
