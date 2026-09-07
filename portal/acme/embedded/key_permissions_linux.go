//go:build linux

package embedded

import (
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
	if err := validateKeyDirectory(dir); err != nil {
		return nil, err
	}
	return os.CreateTemp(dir, ".dnssec-key-*")
}
