//go:build !unix

package pepper

import "errors"

func lockMemory(buf []byte) error {
	return errors.New("mlock is unavailable on this platform")
}

func unlockMemory(buf []byte) error {
	return errors.New("mlock is unavailable on this platform")
}
