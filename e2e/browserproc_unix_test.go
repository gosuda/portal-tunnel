//go:build unix

package e2e_test

import (
	"os/exec"
	"syscall"
)

// browserTree owns the browser process tree teardown. The browser runs in its
// own process group so cleanup can signal the whole tree even after a
// launcher hands off to a real browser process.
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

// kill ends every process in the browser tree; it is safe to call twice.
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

// browserSysProcAttr puts the browser in its own process group so the whole
// tree can be signalled together.
func browserSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
