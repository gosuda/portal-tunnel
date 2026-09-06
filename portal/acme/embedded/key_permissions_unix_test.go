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
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/gosuda/portal-tunnel/v2/types"
)

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
	if err != nil || len(data) == 0 {
		t.Fatalf("did not reach completed key publication: %v", err)
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
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, data) {
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
	path := filepath.Join(parent, "new", "nested", types.DNSSECKeyFileName)
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
