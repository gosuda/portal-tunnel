//go:build !windows

package acme

import "os"

// The state directory must already exist and be durable. Sync establishes the
// journal directory entry before a newly created file can authorize a CA order.
func syncTenantJournalDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
