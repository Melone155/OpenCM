//go:build windows

package inventory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func powershellPath() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(p); err == nil {
			return p // absolute path: no PATH hijacking when running as SYSTEM
		}
	}
	return "powershell.exe"
}

func collectOS(ctx context.Context, inv *Inventory) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, powershellPath(),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShell(windowsScript))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("windows inventory script: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if err := applyWindowsJSON(out, inv); err != nil {
		return fmt.Errorf("parse windows inventory: %w", err)
	}
	// security posture: separate script, best effort (an error leaves the section empty)
	sec := exec.CommandContext(ctx, powershellPath(),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePowerShell(windowsSecurityScript))
	if out, err := sec.Output(); err == nil {
		if s, err := applyWindowsSecurityJSON(out); err == nil {
			inv.Security = s
		}
	}
	return nil
}

// MachineID returns the Windows MachineGuid (stable per OS installation).
func MachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	return "win-" + strings.ToLower(v), nil
}

// OSVersion returns a short OS description for enrolment.
func OSVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	display, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	// Windows 11 still reports "Windows 10" in ProductName; the build number disambiguates.
	if strings.HasPrefix(name, "Windows 10") && build >= "22000" && len(build) == 5 {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s", name, display))
}

// LoggedOnUsers is a cheap check used by the heartbeat (console + RDP sessions via quser).
// quser is missing on Windows Home editions → nil (the inventory still reports users).
func LoggedOnUsers(ctx context.Context) []string {
	quser := ""
	if root := os.Getenv("SystemRoot"); root != "" {
		quser = filepath.Join(root, "System32", "quser.exe")
	}
	if _, err := os.Stat(quser); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// quser exits with 1 when nobody is logged on – output is still parsed.
	out, _ := exec.CommandContext(ctx, quser).Output()
	return parseQuser(string(out))
}
