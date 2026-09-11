//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package embedded

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestDNSSECNewKeyPathsArePrivate(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "private", "dnssec")
	path := filepath.Join(dir, types.DNSSECKeyFileName)
	p := newTestProvider(t, func(cfg *Config) { cfg.KeyPath = path })
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}

	for _, created := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(parent, "private"), 0700},
		{dir, 0700},
		{path, 0600},
	} {
		info, err := os.Stat(created.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != created.mode {
			t.Fatalf("%q mode = %04o, want %04o", created.path, info.Mode().Perm(), created.mode)
		}
	}
}
