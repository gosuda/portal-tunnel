//go:build !windows

package utils

import (
	"errors"
	"os"
)

func EnsurePrivateDir(path string) error {
	return os.MkdirAll(path, 0o700)
}

func EnsurePrivateFile(string) error {
	return nil
}

// CreatePrivateFile never replaces an existing identity.
func CreatePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
