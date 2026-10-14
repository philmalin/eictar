//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// ownGroup puts the command in a process group of its own, with each
// process that it starts.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup stops each process that is left in the group of the command.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
