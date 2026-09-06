//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package embedded

import (
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
