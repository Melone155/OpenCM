//go:build darwin

// Package service integrates the agent with the OS service manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
)

const (
	Name      = "org.opencm.agent"
	plistPath = "/Library/LaunchDaemons/org.opencm.agent.plist"
	logDir    = "/Library/Logs/OpenCM"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.opencm.agent</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/Library/Logs/OpenCM/agent.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/OpenCM/agent.log</string>
</dict>
</plist>
`

// IsService is false on macOS: launchd runs the agent in the foreground.
func IsService() bool { return false }

func RunService(func(ctx context.Context)) error { return errors.New("not supported on macOS") }

func launchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func Install(exe string) error {
	if os.Geteuid() != 0 {
		return errors.New("install requires root")
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(fmt.Sprintf(plistTemplate, html.EscapeString(exe))), 0o644); err != nil {
		return err
	}
	_ = launchctl("bootout", "system/"+Name) // ignore "not loaded"
	if err := launchctl("bootstrap", "system", plistPath); err != nil {
		return err
	}
	return launchctl("enable", "system/"+Name)
}

func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall requires root")
	}
	_ = launchctl("bootout", "system/"+Name)
	if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
