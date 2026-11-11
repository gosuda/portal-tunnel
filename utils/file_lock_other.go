//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package utils

import "os"

// Automatic certificate state requires an operating-system advisory lock.
func TryLockFile(string) (*os.File, error) {
	return nil, ErrFileLocked
}
