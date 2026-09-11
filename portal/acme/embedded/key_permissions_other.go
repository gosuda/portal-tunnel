//go:build !windows

package embedded

import (
	"errors"
	"os"
	"path/filepath"
)

func createKeyTempFile(dir string) (*os.File, error) {
	// os.CreateTemp creates the file with mode 0600 before any key material is
	// written. Existing operator-managed directory permissions are left alone.
	return os.CreateTemp(dir, ".dnssec-key-*")
}

func publishKeyFile(tmp, path string) error {
	return os.Link(tmp, path)
}

func makeKeyDirectory(dir string) error {
	return os.MkdirAll(dir, 0700)
}

func syncKeyPublication(path string) error {
	// Syncing the file does not persist its directory entry on Unix.
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}
