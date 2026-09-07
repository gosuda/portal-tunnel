//go:build !windows && !linux

package embedded

import "os"

// Non-Linux systems retain the previous storage policy: temporary files use
// mode 0600, and loadSigningKey rejects permissive existing private keys.
// This path does not inspect ownership or extended ACLs.
func restrictKeyPermissions(string) error { return nil }

func createKeyTempFile(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".dnssec-key-*")
}
