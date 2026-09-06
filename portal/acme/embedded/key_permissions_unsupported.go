//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package embedded

import (
	"errors"
	"os"
)

var errUnsupportedDNSSECKeyStorage = errors.New("dnssec key storage is unsupported on this platform")

func restrictKeyPermissions(string) error {
	return errUnsupportedDNSSECKeyStorage
}

func createKeyTempFile(string) (*os.File, error) {
	return nil, errUnsupportedDNSSECKeyStorage
}

func publishKeyFile(string, string) error {
	return errUnsupportedDNSSECKeyStorage
}

func makeKeyDirectory(string) error {
	return errUnsupportedDNSSECKeyStorage
}

func syncKeyPublication(string) error {
	return errUnsupportedDNSSECKeyStorage
}
