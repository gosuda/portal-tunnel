//go:build unix

package e2e_test

import (
	"os"
	"syscall"
	"testing"
)

func stdinSocketPair(t *testing.T) (child, owner *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	child, owner = os.NewFile(uintptr(fds[0]), "stdin-child"), os.NewFile(uintptr(fds[1]), "stdin-owner")
	t.Cleanup(func() {
		child.Close()
		owner.Close()
	})
	return child, owner
}
