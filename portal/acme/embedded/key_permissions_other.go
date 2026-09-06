//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package embedded

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Temporary file creation uses mode 0600; existing files are inspected, never
// repaired. A private mode alone cannot make a foreign-owned key trustworthy.
func restrictKeyPermissions(path string) error {
	// Existing keys bypass makeKeyDirectory, including publication race losers.
	if err := validateKeyDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect dnssec private key %q owner: %w", path, err)
	}
	if !trustedKeyOwner(info) {
		return fmt.Errorf("unsafe dnssec private key %q: owner must be effective service UID %d or root; have an administrator review ownership before retrying; key contents, ownership, and permissions were not changed", path, os.Geteuid())
	}
	return nil
}

func trustedKeyOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func validateKeyDirectory(dir string) error {
	unsafeDirectory := func(reason string) error {
		return fmt.Errorf("unsafe dnssec key directory %q: %s; have an administrator review its ownership and remove group/other write access (including effective ACL write grants) before retrying; directory and sibling ownership and permissions were not changed", dir, reason)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("inspect dnssec key directory %q owner and permissions: %w", dir, err)
	}
	if !info.IsDir() {
		return unsafeDirectory("not a directory")
	}
	if !trustedKeyOwner(info) {
		return unsafeDirectory(fmt.Sprintf("owner must be effective service UID %d or root", os.Geteuid()))
	}
	// Linux reports the POSIX ACL mask in the group mode bits, so any
	// effective named-user/group write grant sets this bit too. Conservatively
	// reject a writable mask even when no ACL entry uses it, and even for a
	// service-only group. Read/traverse access is safe and remains unchanged.
	if info.Mode().Perm()&0022 != 0 {
		return unsafeDirectory(fmt.Sprintf("mode %04o permits group/other writes", info.Mode().Perm()))
	}
	return nil
}

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
		// succeeded here, once per entry. Cooperating EEXIST callers never gain
		// rollback ownership; their children make parent removal fail. External
		// namespace replacement must not race initialization: pathname removal
		// cannot atomically compare ownership against a janitor or operator.
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
	if err := validateKeyDirectory(dir); err != nil {
		return rollback(err)
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
