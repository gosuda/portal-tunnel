//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package keyless

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockCertificate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errAutomaticCertificateBusy
		}
		return nil, err
	}
	return f, nil // Closing the descriptor releases the operating-system lock.
}
