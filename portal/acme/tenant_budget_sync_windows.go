//go:build windows

package acme

// Windows file.Sync uses FlushFileBuffers, which flushes file data and metadata.
// Directory handles do not support FlushFileBuffers. The state directory must
// already have been provisioned durably by the operator.
func syncTenantJournalDirectory(string) error { return nil }
