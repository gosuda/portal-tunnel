//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package embedded

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
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

func TestDNSSECKeyPublicationSyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a directory without read permission")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	// Write/search permissions allow creation and publication, but not opening
	// the directory for fsync. Exercise a real OS error without a test hook.
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Errorf("restore key directory permissions: %v", err)
		}
	})
	cfg := Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path}
	for range 2 {
		// The first call publishes, the second finds that completed key at its
		// initial stat. Neither may expose a key while the flush still fails.
		p, err := New(cfg)
		if err == nil {
			_ = p.Stop()
			t.Fatal("exposed a key without persisting its directory entry")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected directory sync permission failure: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read published key after directory sync failure: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("published key is empty after directory sync failure")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := response.Answer[0].(*dns.DNSKEY)
	verifySection(t, key, response.Answer)
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() {
		t.Fatalf("restart did not expose a usable key and DS: %q (%v)", ds, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read published key after restart: %v", err)
	}
	if !bytes.Equal(after, data) {
		t.Fatal("restart changed the key after a publication sync failure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != types.DNSSECKeyFileName {
		t.Fatalf("publication sync failure left temporary files: %v", entries)
	}
}

func TestDNSSECKeyDirectoryDurability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a directory without read permission")
	}
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0700); err != nil {
			t.Errorf("restore parent directory permissions: %v", err)
		}
	})

	// An existing key directory must not require read/fsync access to its
	// ancestors: search permission is sufficient to use the key directory.
	newTestProvider(t, func(cfg *Config) {
		cfg.KeyPath = filepath.Join(existing, types.DNSSECKeyFileName)
	})

	// Creating a directory tree does require persisting each new entry,
	// including the entry in the first pre-existing parent.
	created := filepath.Join(parent, "new")
	path := filepath.Join(created, "nested", types.DNSSECKeyFileName)
	for range 2 {
		p, err := New(Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path})
		if err == nil {
			_ = p.Stop()
			t.Fatal("exposed a key inside an unpersisted directory tree")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected new directory entry sync failure: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published a key before persisting its directory tree: %v", err)
		}
		if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed initialization left an unpersisted directory for the next retry to trust: %v", err)
		}
	}

	// Once the storage boundary becomes flushable, retry must need no manual
	// directory cleanup and must publish one stable key and parent DS.
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := response.Answer[0].(*dns.DNSKEY)
	verifySection(t, key, response.Answer)
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() {
		t.Fatalf("retry did not publish a usable key and DS: %q (%v)", ds, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key after directory creation retry: %v", err)
	}
	restarted := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	response = dnssecExchange(t, restarted, "tcp", testZone, dns.TypeDNSKEY, 1232)
	verifySection(t, key, response.Answer)
	_, restartedDS, _, err := restarted.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || restartedDS != ds {
		t.Fatalf("restart changed the DS after directory creation retry: %q => %q (%v)", ds, restartedDS, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key after directory retry and restart: %v", err)
	}
	if !bytes.Equal(after, data) {
		t.Fatal("restart changed the key after directory creation retry")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != types.DNSSECKeyFileName {
		t.Fatalf("directory creation retry left temporary files: %v", entries)
	}
}

func TestDNSSECKeyWriteFailure(t *testing.T) {
	const childPathEnv = "PORTAL_TEST_DNSSEC_KEY_WRITE_LIMIT_PATH"
	if path := os.Getenv(childPathEnv); path != "" {
		// A subprocess contains the process-wide limit and signal disposition.
		// Permit one byte so this exercises a partial write, not just creation.
		var original unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		limited := original
		limited.Cur = 1
		signal.Ignore(unix.SIGXFSZ)
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		// Keep the hard limit intact and restore before the test binary writes coverage.
		t.Cleanup(func() {
			if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
				t.Errorf("restore file-size limit: %v", err)
			}
		})
		p, err := New(Config{BaseDomain: testZone, ListenAddr: "127.0.0.1:0", KeyPath: path})
		if err == nil {
			_ = p.Stop()
			t.Fatal("published a key despite the file-size limit")
		}
		if !errors.Is(err, unix.EFBIG) && !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("did not reach the private key write: %v", err)
		}
		return
	}

	dir := t.TempDir()
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestDNSSECKeyWriteFailure$")
	cmd.Env = append(os.Environ(), childPathEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("key write failure subprocess: %v\n%s", err, output)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial key was published: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed key write left temporary files: %v", entries)
	}

	// With the transient limit gone, restart must work without manual cleanup.
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	response := dnssecExchange(t, p, "tcp", testZone, dns.TypeDNSKEY, 1232)
	key := response.Answer[0].(*dns.DNSKEY)
	verifySection(t, key, response.Answer)
	_, ds, _, err := p.EnsureDNSSEC(context.Background(), testZone)
	if err != nil || ds != key.ToDS(dns.SHA256).String() {
		t.Fatalf("retry did not publish a usable key and DS: %q (%v)", ds, err)
	}
}
