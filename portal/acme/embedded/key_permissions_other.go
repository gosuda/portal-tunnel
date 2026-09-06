//go:build !windows

package embedded

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Temporary file creation uses mode 0600; loading separately rejects permissive
// existing files rather than silently changing administrator-owned permissions.
func restrictKeyPermissions(string) error { return nil }

func createKeyTempFile(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".dnssec-key-*")
}

func publishKeyFile(tmp, path string) error {
	return os.Link(tmp, path)
}

func makeKeyDirectory(dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	type directory struct {
		path    string
		created bool
	}
	var missing []directory
	for current := dir; ; current = filepath.Dir(current) {
		info, statErr := os.Stat(current)
		if statErr == nil {
			if !info.IsDir() {
				return fmt.Errorf("dnssec key directory %q is not a directory", current)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) || filepath.Dir(current) == current {
			return statErr
		}
		missing = append(missing, directory{path: current})
	}
	rollback := func(cause error) error {
		// Walk back from the leaf and remove only empty directories whose Mkdir
		// succeeded here. Never remove a racing creator's directory or contents.
		for _, entry := range missing {
			if !entry.created {
				continue
			}
			if err := os.Remove(entry.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				cause = errors.Join(cause, fmt.Errorf("remove unpersisted dnssec key directory %q: %w", entry.path, err))
			}
		}
		return cause
	}
	for i := len(missing) - 1; i >= 0; i-- {
		entry := &missing[i]
		if err := os.Mkdir(entry.path, 0700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return rollback(err)
			}
			info, statErr := os.Stat(entry.path)
			if statErr != nil {
				return rollback(statErr)
			}
			if !info.IsDir() {
				return rollback(fmt.Errorf("dnssec key directory %q is not a directory", entry.path))
			}
		} else {
			entry.created = true
		}
		// Persist each new entry before creating its children, including entries
		// just created by a racer. Stop at the first pre-existing storage boundary;
		// existing directory permissions and unrelated ancestors stay untouched.
		if err := syncKeyPublication(entry.path); err != nil {
			return rollback(err)
		}
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
