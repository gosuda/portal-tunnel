//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package keyless

import "os"

// Automatic certificate state requires an operating-system advisory lock.
func lockCertificate(string) (*os.File, error) {
	return nil, errAutomaticCertificateBusy
}
