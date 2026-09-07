//go:build linux

package embedded

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type unixKeyPathSnapshot struct {
	info os.FileInfo
	data []byte
}

func snapshotUnixKeyPaths(t *testing.T, paths ...string) map[string]unixKeyPathSnapshot {
	t.Helper()
	snapshots := make(map[string]unixKeyPathSnapshot, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		if !info.IsDir() {
			data, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		snapshots[path] = unixKeyPathSnapshot{info: info, data: data}
	}
	return snapshots
}

func requireUnixKeyPathsUnchanged(t *testing.T, before map[string]unixKeyPathSnapshot) {
	t.Helper()
	for path, snapshot := range before {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		owner := snapshot.info.Sys().(*syscall.Stat_t)
		afterOwner := info.Sys().(*syscall.Stat_t)
		if !os.SameFile(snapshot.info, info) || info.Mode() != snapshot.info.Mode() || owner.Uid != afterOwner.Uid || owner.Gid != afterOwner.Gid {
			t.Errorf("changed existing path %q identity, ownership, or mode: %v => %v", path, snapshot.info.Mode(), info.Mode())
		}
		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, snapshot.data) {
				t.Errorf("changed existing file %q contents: %v", path, err)
			}
		}
	}
}

func newUnixKeyDirectory(t *testing.T) (dir, path, sibling string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, types.DNSSECKeyFileName)
	sibling = filepath.Join(dir, "operator.pem")
	if err := os.WriteFile(sibling, []byte("operator-managed certificate"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sibling, 0640); err != nil {
		t.Fatal(err)
	}
	return dir, path, sibling
}

func persistUnixSigningKey(t *testing.T, path string) string {
	t.Helper()
	p, err := New(Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	stopErr := p.Stop()
	if err != nil || stopErr != nil {
		t.Fatalf("prepare persisted key: %v", errors.Join(err, stopErr))
	}
	if ds == "" {
		t.Fatal("persisted key has no parent DS")
	}
	return ds
}

func requireUnixSigningKey(t *testing.T, path string, before map[string]unixKeyPathSnapshot) string {
	t.Helper()
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := response.Answer[0].(*dns.DNSKEY)
	verifySection(t, key, response.Answer)
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() {
		t.Fatalf("accepted directory lost its signing key or parent DS: %q (%v)", ds, err)
	}
	requireUnixKeyPathsUnchanged(t, before)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %v, want 0600", info.Mode())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Fatalf("accepted directory left unexpected entries: %v (%v)", entries, err)
	}
	return ds
}

func requireUnixKeyRejection(t *testing.T, path, target, reason string, before map[string]unixKeyPathSnapshot) {
	t.Helper()
	p, err := New(Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path})
	if err == nil {
		_ = p.Stop()
		t.Fatal("accepted an unsafe signing store")
	}
	identifiesTarget := strings.Contains(err.Error(), target)
	explainsPolicy := strings.Contains(err.Error(), reason)
	offersRemediation := strings.Contains(err.Error(), "administrator")
	if !identifiesTarget || !explainsPolicy || !offersRemediation {
		t.Fatalf("expected actionable signing policy rejection, not an incidental failure: %v", err)
	}
	requireUnixKeyPathsUnchanged(t, before)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != len(before)-1 {
		t.Fatalf("rejected signing store changed directory entries: %v (%v)", entries, err)
	}
}

func TestDNSSECKeyDirectoryPermissionsNewKey(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, path, sibling := newUnixKeyDirectory(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			before := snapshotUnixKeyPaths(t, dir, sibling)
			requireUnixSigningKey(t, path, before)
		})
	}
}

func TestDNSSECKeyDirectoryPermissionsExistingKey(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, path, sibling := newUnixKeyDirectory(t)
			originalDS := persistUnixSigningKey(t, path)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			before := snapshotUnixKeyPaths(t, dir, sibling, path)
			if ds := requireUnixSigningKey(t, path, before); ds != originalDS {
				t.Fatalf("accepted directory changed the parent DS: %q => %q", originalDS, ds)
			}
		})
	}
}

func TestDNSSECKeyDirectoryRejectsNewKey(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0770, 0702} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, path, sibling := newUnixKeyDirectory(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			before := snapshotUnixKeyPaths(t, dir, sibling)
			for range 2 {
				requireUnixKeyRejection(t, path, "unsafe dnssec key directory", "group/other write", before)
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("published a key in an unsafe directory: %v", err)
				}
			}
			// An explicit operator correction retains shared read/traverse access.
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			before = snapshotUnixKeyPaths(t, dir, sibling)
			requireUnixSigningKey(t, path, before)
		})
	}
}

func TestDNSSECKeyDirectoryRejectsExistingKey(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0770, 0702} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, path, sibling := newUnixKeyDirectory(t)
			originalDS := persistUnixSigningKey(t, path)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			before := snapshotUnixKeyPaths(t, dir, sibling, path)
			for range 2 {
				requireUnixKeyRejection(t, path, "unsafe dnssec key directory", "group/other write", before)
			}
			// Repairing only the directory must retain the exact key and parent DS.
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			before = snapshotUnixKeyPaths(t, dir, sibling, path)
			if ds := requireUnixSigningKey(t, path, before); ds != originalDS {
				t.Fatalf("operator chmod correction changed the parent DS: %q => %q", originalDS, ds)
			}
		})
	}
}

func TestDNSSECNewNestedKeyDirectoriesArePrivate(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(parent, "operator.pem")
	if err := os.WriteFile(sibling, []byte("operator-managed certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	before := snapshotUnixKeyPaths(t, parent, sibling)
	first := filepath.Join(parent, "private")
	dir := filepath.Join(first, "nested")
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	requireUnixKeyPathsUnchanged(t, before)
	for _, created := range []string{first, dir, path} {
		info, err := os.Stat(created)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0700)
		if created == path {
			want = 0600
		}
		if info.Mode().Perm() != want || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			t.Fatalf("new signing path %q is not service-owned and private: %v", created, info.Mode())
		}
	}
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil {
		t.Fatal(err)
	}
	before = snapshotUnixKeyPaths(t, parent, sibling, first, dir, path)
	restarted := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	_, restartedDS, _, err := restarted.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || restartedDS != ds {
		t.Fatalf("nested directory restart changed the parent DS: %q => %q (%v)", ds, restartedDS, err)
	}
	requireUnixKeyPathsUnchanged(t, before)
}

func requireUnixForeignOwner(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to establish and inspect foreign-owned 0600 key fixtures")
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("cannot establish foreign-owned fixture: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chown(path, 0, -1); err != nil {
			t.Errorf("restore fixture ownership: %v", err)
		}
	})
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Skip("filesystem did not establish the requested foreign UID")
	}
}

func TestDNSSECKeyOwnershipNewDirectory(t *testing.T) {
	dir, path, sibling := newUnixKeyDirectory(t)
	requireUnixForeignOwner(t, dir)
	before := snapshotUnixKeyPaths(t, dir, sibling)
	requireUnixKeyRejection(t, path, "unsafe dnssec key directory", "owner must be effective service UID", before)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published a key in a foreign-owned directory: %v", err)
	}
	if err := os.Chown(dir, 0, -1); err != nil {
		t.Fatal(err)
	}
	before = snapshotUnixKeyPaths(t, dir, sibling)
	requireUnixSigningKey(t, path, before)
}

func TestDNSSECKeyOwnershipExistingDirectory(t *testing.T) {
	dir, path, sibling := newUnixKeyDirectory(t)
	originalDS := persistUnixSigningKey(t, path)
	requireUnixForeignOwner(t, dir)
	before := snapshotUnixKeyPaths(t, dir, sibling, path)
	requireUnixKeyRejection(t, path, "unsafe dnssec key directory", "owner must be effective service UID", before)
	// Restoring trusted directory ownership must retain the exact key/DS.
	if err := os.Chown(dir, 0, -1); err != nil {
		t.Fatal(err)
	}
	before = snapshotUnixKeyPaths(t, dir, sibling, path)
	if ds := requireUnixSigningKey(t, path, before); ds != originalDS {
		t.Fatalf("directory ownership correction changed the parent DS: %q => %q", originalDS, ds)
	}
}

func TestDNSSECKeyOwnershipExistingKey(t *testing.T) {
	dir, path, sibling := newUnixKeyDirectory(t)
	originalDS := persistUnixSigningKey(t, path)
	requireUnixForeignOwner(t, path)
	before := snapshotUnixKeyPaths(t, dir, sibling, path)
	requireUnixKeyRejection(t, path, "unsafe dnssec private key", "owner must be effective service UID", before)
	// Mode 0600 stays unchanged throughout ownership rejection and correction.
	if err := os.Chown(path, 0, -1); err != nil {
		t.Fatal(err)
	}
	before = snapshotUnixKeyPaths(t, dir, sibling, path)
	if ds := requireUnixSigningKey(t, path, before); ds != originalDS {
		t.Fatalf("key ownership correction changed the parent DS: %q => %q", originalDS, ds)
	}
}
