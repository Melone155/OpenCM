//go:build linux

// Package service integrates the agent with the OS service manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	Name     = "opencm-agent"
	unitPath = "/etc/systemd/system/opencm-agent.service"
)

const unitTemplate = `[Unit]
Description=OpenCM Agent
Documentation=https://github.com/opencm/opencm
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=10
# The agent needs root for full inventory and (from M2) job execution.
User=root
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
`

// IsService is false on Linux: systemd runs the agent in the foreground and
// stops it via SIGTERM, which `run` handles.
func IsService() bool { return false }

func RunService(func(ctx context.Context)) error { return errors.New("not supported on linux") }

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func Install(exe string) error {
	if os.Geteuid() != 0 {
		return errors.New("install requires root")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd not found – start `opencm-agent run` with your init system")
	}
	if strings.ContainsAny(exe, " \t\n") {
		return fmt.Errorf("executable path must not contain whitespace: %q", exe)
	}
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unitTemplate, exe)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", Name)
}

func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall requires root")
	}
	_ = systemctl("disable", "--now", Name)
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return systemctl("daemon-reload")
}
