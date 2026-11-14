//go:build windows

package e2e_test

import (
	"os"
	"testing"
)

func stdinSocketPair(t *testing.T) (child, owner *os.File) {
	t.Skip("Windows runtimes pass piped stdin as named pipes")
	return nil, nil
}
