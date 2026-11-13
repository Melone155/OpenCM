//go:build darwin

package inventory

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

func collectOS(ctx context.Context, inv *Inventory) error {
	// SPApplicationsDataType can take a while on machines with many apps.
	if out, err := run(ctx, 5*time.Minute, "/usr/sbin/system_profiler", "-json", "-detailLevel", "mini",
		"SPHardwareDataType", "SPSoftwareDataType", "SPApplicationsDataType"); err == nil {
		if err := applySystemProfiler([]byte(out), inv); err != nil {
			return err
		}
	}
	inv.OS.Arch = sp(goArchToMachine())
	if out, err := run(ctx, 10*time.Second, "/usr/sbin/sysctl", "-n", "hw.logicalcpu"); err == nil {
		var n float64
		for _, c := range strings.TrimSpace(out) {
			if c < '0' || c > '9' {
				n = 0
				break
			}
			n = n*10 + float64(c-'0')
		}
		inv.Hardware.CPU.LogicalProcessors = fp(n)
	}
	if out, err := run(ctx, 10*time.Second, "/usr/sbin/sysctl", "-n", "kern.boottime"); err == nil {
		inv.OS.LastBoot = sp(parseKernBoottime(out))
	}
	if inv.Hardware.Model != nil && strings.Contains(strings.ToLower(*inv.Hardware.Model), "virtual") {
		inv.Hardware.Chassis = sp("Virtual Machine")
	} else if inv.Hardware.Model != nil && strings.Contains(*inv.Hardware.Model, "Book") {
		inv.Hardware.Chassis = sp("Laptop")
	} else {
		inv.Hardware.Chassis = sp("Desktop")
	}

	if out, err := run(ctx, time.Minute, "/bin/df", "-kP"); err == nil {
		inv.Disks = parseDF(out)
	}
	if out, err := run(ctx, time.Minute, "/bin/launchctl", "list"); err == nil {
		inv.Services = parseLaunchctlList(out)
	}
	if out, err := run(ctx, time.Minute, "/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"); err == nil {
		inv.LocalUsers = parseDsclUsers(out)
	}
	if out, err := run(ctx, time.Minute, "/usr/bin/dscl", ".", "-list", "/Groups", "GroupMembership"); err == nil {
		inv.LocalGroups = parseDsclGroups(out)
	}
	if out, err := run(ctx, time.Minute, "/usr/sbin/softwareupdate", "--history"); err == nil {
		inv.Patches = parseSoftwareUpdateHistory(out)
	}
	inv.LoggedOnUsers = LoggedOnUsers(ctx)
	inv.Security = collectSecurityDarwin(ctx)
	return nil
}

var reBoottime = regexp.MustCompile(`sec = (\d+)`)

// "{ sec = 1731398400, usec = 0 } Tue Nov 12 08:00:00 2024"
func parseKernBoottime(s string) string {
	m := reBoottime.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	var n int64
	for _, c := range m[1] {
		n = n*10 + int64(c-'0')
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// parseSoftwareUpdateHistory parses `softwareupdate --history`:
// "Display Name                 Version    Date" followed by aligned rows.
func parseSoftwareUpdateHistory(s string) []Patch {
	var out []Patch
	re := regexp.MustCompile(`^(.+?)\s{2,}(\S+)\s{2,}(\S+.*)$`)
	for i, l := range lines(s) {
		if i < 2 {
			continue // header + dashes
		}
		m := re.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		out = append(out, Patch{ID: m[1] + " " + m[2], Description: sp(m[1]), InstalledOn: sp(strings.TrimSpace(m[3]))})
	}
	return out
}

func MachineID() (string, error) {
	out, err := run(context.Background(), 10*time.Second, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`).FindStringSubmatch(out)
	if m == nil {
		return "", errors.New("IOPlatformUUID not found")
	}
	return "mac-" + strings.ToLower(m[1]), nil
}

func OSVersion() string {
	name, _ := run(context.Background(), 5*time.Second, "/usr/bin/sw_vers", "-productName")
	ver, _ := run(context.Background(), 5*time.Second, "/usr/bin/sw_vers", "-productVersion")
	return strings.TrimSpace(strings.TrimSpace(name) + " " + strings.TrimSpace(ver))
}

func LoggedOnUsers(ctx context.Context) []string {
	out, err := run(ctx, 5*time.Second, "/usr/bin/stat", "-f%Su", "/dev/console")
	u := strings.TrimSpace(out)
	if err != nil || u == "" || u == "root" {
		return nil
	}
	return []string{u}
}
