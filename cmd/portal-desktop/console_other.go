//go:build !windows

package main

import "os/exec"

// hideConsole does nothing outside Windows, where a program that the desktop
// starts opens no window of its own.
func hideConsole(*exec.Cmd) {}
