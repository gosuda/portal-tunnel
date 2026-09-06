//go:build !windows

package embedded

// Creation uses O_EXCL and mode 0600; loading separately rejects permissive
// existing files rather than silently changing administrator-owned permissions.
func restrictKeyPermissions(string) error { return nil }
