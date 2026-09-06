//go:build !windows

package embedded

import (
	"errors"
	"os"
	"path/filepath"
)

// Temporary file creation uses mode 0600; loading separately rejects permissive
// existing files rather than silently changing administrator-owned permissions.
func restrictKeyPermissions(string) error { return nil }

func publishKeyFile(tmp, path string) error {
	return os.Link(tmp, path)
}

func makeKeyDirectory(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	existing := dir
	for {
		_, statErr := os.Stat(existing)
		if statErr == nil {
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) || filepath.Dir(existing) == existing {
			return statErr
		}
		existing = filepath.Dir(existing)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// Only new directory entries need flushing here. Do not impose read/fsync
	// requirements on unrelated ancestors of an existing key directory.
	for dir != existing {
		if err := syncKeyPublication(dir); err != nil {
			return err
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

func syncKeyPublication(path string) error {
	// Syncing the file does not persist its directory entry on Unix. A reader
	// must flush the directory too, even if another creator published the key.
	// Unsupported directory fsync is an error, never a successful fallback.
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}
