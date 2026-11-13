//go:build !windows

package tasks

import (
	"os/exec"
	"syscall"
)

// setupProcess puts the child in its own process group so the whole tree can be killed.
func setupProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// negative pid = process group
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
