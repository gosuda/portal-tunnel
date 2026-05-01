//go:build unix

package pepper

import "golang.org/x/sys/unix"

func lockMemory(buf []byte) error {
	return unix.Mlock(buf)
}

func unlockMemory(buf []byte) error {
	return unix.Munlock(buf)
}
