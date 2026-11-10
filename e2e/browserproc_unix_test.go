//go:build unix

package e2e_test

import (
	"os/exec"
	"syscall"
)

type browserTree struct {
	pid  int
	done bool
}

func newBrowserTree(cmd *exec.Cmd) *browserTree {
	if cmd == nil || cmd.Process == nil {
		return &browserTree{}
	}
	return &browserTree{pid: cmd.Process.Pid}
}

func (b *browserTree) kill() error {
	if b == nil || b.done {
		return nil
	}
	b.done = true
	if b.pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-b.pid, syscall.SIGKILL); err != nil {
		return syscall.Kill(b.pid, syscall.SIGKILL)
	}
	return nil
}

func browserSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
