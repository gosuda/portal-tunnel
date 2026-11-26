package main

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// hideConsole starts the console program of cmd without a console window.
// The desktop has no console, so Windows would open one for the program.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
