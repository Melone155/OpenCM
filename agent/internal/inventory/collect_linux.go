//go:build linux

package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func dmi(name string) string {
	v := readFile("/sys/class/dmi/id/" + name)
	switch strings.ToLower(v) {
	case "", "to be filled by o.e.m.", "default string", "not specified", "system serial number", "none":
		return ""
	}
	return v
}

var chassisTypes = map[string]string{
	"3": "Desktop", "4": "Low Profile Desktop", "6": "Mini Tower", "7": "Tower", "8": "Portable", "9": "Laptop",
	"10": "Notebook", "13": "All in One", "14": "Sub Notebook", "17": "Main Server Chassis", "23": "Rack Mount Chassis",
	"30": "Tablet", "31": "Convertible", "32": "Detachable", "35": "Mini PC", "1": "Other",
}

func collectOS(ctx context.Context, inv *Inventory) error {
	// hardware
	inv.Hardware.Manufacturer = sp(dmi("sys_vendor"))
	inv.Hardware.Model = sp(dmi("product_name"))
	inv.Hardware.SerialNumber = sp(dmi("product_serial")) // readable as root only
	inv.Hardware.BiosVendor = sp(dmi("bios_vendor"))
	inv.Hardware.BiosVersion = sp(dmi("bios_version"))
	inv.Hardware.BiosDate = sp(dmi("bios_date"))
	if c, ok := chassisTypes[dmi("chassis_type")]; ok {
		inv.Hardware.Chassis = sp(c)
	}
	if v := readFile("/sys/hypervisor/type"); v != "" || strings.Contains(strings.ToLower(dmi("product_name")), "virtual") {
		inv.Hardware.Chassis = sp("Virtual Machine")
	}
	model, cores, logical, mhz := parseCPUInfo(readFile("/proc/cpuinfo"))
	inv.Hardware.CPU = CPU{Model: sp(model), Cores: fp(float64(cores)), LogicalProcessors: fp(float64(logical)), MHz: fp(mhz)}
	inv.Hardware.MemoryBytes = fp(parseMemInfoTotal(readFile("/proc/meminfo")))

	// OS
	rel := parseOSRelease(readFile("/etc/os-release"))
	name := rel["NAME"]
	if name == "" {
		name = "Linux"
	}
	inv.OS = OSInfo{
		Name:     sp(name),
		Version:  sp(firstNonEmpty(rel["VERSION"], rel["VERSION_ID"])),
		Build:    sp(rel["VERSION_ID"]),
		Arch:     sp(goArchToMachine()),
		Kernel:   sp(readFile("/proc/sys/kernel/osrelease")),
		LastBoot: sp(parseBootTime(readFile("/proc/stat"))),
		DistroID: sp(strings.ToLower(rel["ID"])),
	}

	// disks
	for _, m := range parseMounts(readFile("/proc/mounts")) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(m.point, &st); err != nil {
			continue
		}
		size := float64(st.Blocks) * float64(st.Bsize)
		free := float64(st.Bavail) * float64(st.Bsize)
		inv.Disks = append(inv.Disks, Disk{Name: m.device, Mount: sp(m.point), FSType: sp(m.fsType), SizeBytes: fp(size), FreeBytes: fp(free)})
	}

	// software
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, _ := run(ctx, 2*time.Minute, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n")
		inv.Software = append(inv.Software, parseDpkg(out)...)
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, _ := run(ctx, 2*time.Minute, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}\t%{EPOCH}\t%{SOURCERPM}\n")
		inv.Software = append(inv.Software, parseRPM(out)...)
	}

	inv.Security = collectSecurityLinux(ctx)

	// services
	if _, err := exec.LookPath("systemctl"); err == nil {
		units, _ := run(ctx, time.Minute, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
		files, _ := run(ctx, time.Minute, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
		inv.Services = parseSystemdUnits(units, files)
	}

	// autostart: XDG autostart entries + enabled timers would be next; M1 covers XDG.
	for _, dir := range []string{"/etc/xdg/autostart"} {
		entries, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
		for _, e := range entries {
			name, execLine, hidden := parseDesktopEntry(readFile(e))
			if hidden || execLine == "" {
				continue
			}
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(e), ".desktop")
			}
			inv.Autostart = append(inv.Autostart, Autostart{Name: name, Command: sp(execLine), Location: sp(dir)})
		}
	}

	// users / groups / sessions
	inv.LocalUsers = parsePasswd(readFile("/etc/passwd"))
	inv.LocalGroups = parseGroup(readFile("/etc/group"))
	inv.LoggedOnUsers = LoggedOnUsers(ctx)
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// MachineID returns /etc/machine-id (systemd) or the D-Bus fallback.
func MachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if v := readFile(p); v != "" {
			return "linux-" + v, nil
		}
	}
	return "", os.ErrNotExist
}

func OSVersion() string {
	rel := parseOSRelease(readFile("/etc/os-release"))
	return firstNonEmpty(rel["PRETTY_NAME"], rel["NAME"], "Linux")
}

func LoggedOnUsers(ctx context.Context) []string {
	out, err := run(ctx, 10*time.Second, "who")
	if err != nil {
		return nil
	}
	return parseWho(out)
}
