package inventory

// OS-neutral parsers for command output and system files. They live in a file
// without build constraints so they are unit-tested on every CI platform.

import (
	"bufio"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, strings.TrimRight(sc.Text(), "\r"))
	}
	return out
}

// ---------------------------------------------------------------- Linux

// parseOSRelease parses /etc/os-release (KEY=value, optionally quoted).
func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, l := range lines(s) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		m[strings.TrimSpace(k)] = v
	}
	return m
}

// parseCPUInfo returns model name, physical cores, logical processors and MHz from /proc/cpuinfo.
func parseCPUInfo(s string) (model string, cores, logical int, mhz float64) {
	type coreKey struct{ phys, core string }
	physCores := map[string]int{} // physical id → "cpu cores"
	seenCores := map[coreKey]bool{}
	var phys, core string
	for _, l := range lines(s) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			if strings.TrimSpace(l) == "" && core != "" {
				seenCores[coreKey{phys, core}] = true
				phys, core = "", ""
			}
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			logical++
		case "model name", "Model", "Hardware": // x86 / ARM variants
			if model == "" {
				model = v
			}
		case "physical id":
			phys = v
		case "core id":
			core = v
		case "cpu cores":
			if n, err := strconv.Atoi(v); err == nil {
				physCores[phys] = n
			}
		case "cpu MHz":
			if mhz == 0 {
				mhz, _ = strconv.ParseFloat(v, 64)
			}
		}
	}
	if core != "" {
		seenCores[coreKey{phys, core}] = true
	}
	for _, n := range physCores {
		cores += n
	}
	if cores == 0 {
		cores = len(seenCores)
	}
	if cores == 0 {
		cores = logical
	}
	return
}

// parseMemInfoTotal returns MemTotal in bytes from /proc/meminfo.
func parseMemInfoTotal(s string) float64 {
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "MemTotal:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				kb, _ := strconv.ParseFloat(f[1], 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// parseBootTime returns the boot time from /proc/stat ("btime <unix>").
func parseBootTime(s string) string {
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "btime ") {
			if n, err := strconv.ParseInt(strings.TrimSpace(l[6:]), 10, 64); err == nil {
				return time.Unix(n, 0).UTC().Format(time.RFC3339)
			}
		}
	}
	return ""
}

// parseDpkg parses: dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Abbrev}\n'
func parseDpkg(s string) []Software {
	var out []Software
	for _, l := range lines(s) {
		f := strings.Split(l, "\t")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		if len(f) >= 5 && !strings.HasPrefix(strings.TrimSpace(f[4]), "ii") {
			continue // not fully installed (rc = removed, config files left)
		}
		sw := Software{Name: f[0], Version: f[1], Publisher: maintainerName(f[2]), Source: "dpkg", Arch: f[3]}
		// ${source:Package} / ${source:Version}: Debian/Ubuntu security advisories are per source package
		if len(f) >= 7 {
			sw.SourceName = sp(strings.TrimSpace(f[5]))
			sw.SourceVersion = sp(strings.TrimSpace(f[6]))
		}
		out = append(out, sw)
	}
	return out
}

// srpmName: "openssl-3.0.7-27.el9.src.rpm" → "openssl" (strip version and release).
func srpmName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "(none)" {
		return ""
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".src.rpm"), ".nosrc.rpm")
	for i := 0; i < 2; i++ {
		j := strings.LastIndex(s, "-")
		if j <= 0 {
			return ""
		}
		s = s[:j]
	}
	return s
}

// "Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>" → "Ubuntu Developers"
func maintainerName(s string) string {
	if i := strings.Index(s, "<"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// parseRPM parses: rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}\t%{EPOCH}\t%{SOURCERPM}\n'
// (the last two fields are optional – older format without them is still accepted).
func parseRPM(s string) []Software {
	var out []Software
	for _, l := range lines(s) {
		f := strings.Split(l, "\t")
		if len(f) < 5 || f[0] == "" || strings.HasPrefix(f[0], "gpg-pubkey") {
			continue
		}
		var date *string
		if n, err := strconv.ParseInt(f[3], 10, 64); err == nil && n > 0 {
			date = sp(time.Unix(n, 0).UTC().Format("2006-01-02"))
		}
		vendor := f[2]
		if vendor == "(none)" {
			vendor = ""
		}
		arch := f[4]
		if arch == "(none)" {
			arch = ""
		}
		sw := Software{Name: f[0], Version: f[1], Publisher: vendor, InstallDate: date, Source: "rpm", Arch: arch}
		if len(f) >= 7 {
			evr := f[1]
			if e := strings.TrimSpace(f[5]); e != "" && e != "(none)" && e != "0" {
				evr = e + ":" + evr
			}
			sw.SourceVersion = sp(evr)
			sw.SourceName = sp(srpmName(f[6]))
		}
		out = append(out, sw)
	}
	return out
}

// parseSystemdUnits combines
//
//	systemctl list-units --type=service --all --no-legend --plain --no-pager
//	  → "ssh.service loaded active running OpenBSD Secure Shell server"
//	systemctl list-unit-files --type=service --no-legend --no-pager
//	  → "ssh.service enabled enabled"
func parseSystemdUnits(units, unitFiles string) []Service {
	startMode := map[string]string{}
	for _, l := range lines(unitFiles) {
		f := strings.Fields(l)
		if len(f) >= 2 {
			startMode[f[0]] = f[1]
		}
	}
	seen := map[string]bool{}
	var out []Service
	for _, l := range lines(units) {
		f := strings.Fields(strings.TrimLeft(l, "●* "))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		seen[f[0]] = true
		desc := strings.Join(f[4:], " ")
		out = append(out, Service{Name: name, DisplayName: sp(desc), State: sp(f[3]), StartMode: sp(startMode[f[0]])})
	}
	// enabled/disabled units that are not loaded right now
	for unit, mode := range startMode {
		if seen[unit] || strings.Contains(unit, "@.") {
			continue
		}
		out = append(out, Service{Name: strings.TrimSuffix(unit, ".service"), State: sp("inactive"), StartMode: sp(mode)})
	}
	return out
}

// parsePasswd parses /etc/passwd. Accounts with uid < 1000 (except root) or a
// nologin shell are reported as disabled for interactive use.
func parsePasswd(s string) []User {
	var out []User
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		shell := f[6]
		noLogin := strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "/false")
		disabled := noLogin || (uid != 0 && uid < 1000)
		gecos, _, _ := strings.Cut(f[4], ",")
		out = append(out, User{Name: f[0], FullName: sp(gecos), Disabled: bp(disabled), UID: sp(f[2])})
	}
	return out
}

// parseGroup parses /etc/group (name:x:gid:member1,member2).
func parseGroup(s string) []Group {
	var out []Group
	for _, l := range lines(s) {
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		members := []string{}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		out = append(out, Group{Name: f[0], Members: members})
	}
	return out
}

// parseWho returns unique user names from `who` output.
func parseWho(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) == 0 || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		out = append(out, f[0])
	}
	return out
}

// realFS lists filesystem types reported as disks (no pseudo/overlay filesystems).
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true,
	"exfat": true, "ntfs": true, "ntfs3": true, "f2fs": true, "jfs": true, "reiserfs": true, "apfs": true, "hfs": true,
}

type mount struct{ device, point, fsType string }

// parseMounts parses /proc/mounts and returns real, de-duplicated mounts.
func parseMounts(s string) []mount {
	seenDev := map[string]bool{}
	var out []mount
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) < 3 || !realFS[f[2]] || seenDev[f[0]] {
			continue
		}
		if strings.HasPrefix(f[1], "/snap/") || strings.HasPrefix(f[1], "/var/lib/docker/") {
			continue
		}
		seenDev[f[0]] = true
		out = append(out, mount{device: f[0], point: unescapeMount(f[1]), fsType: f[2]})
	}
	return out
}

// /proc/mounts escapes spaces etc. as octal (\040).
func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// parseDesktopEntry extracts Name and Exec from a .desktop autostart file.
func parseDesktopEntry(s string) (name, exec string, hidden bool) {
	inEntry := false
	for _, l := range lines(s) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			inEntry = l == "[Desktop Entry]"
			continue
		}
		if !inEntry {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "Name":
			name = v
		case "Exec":
			exec = v
		case "Hidden":
			hidden = strings.EqualFold(v, "true")
		}
	}
	return
}

// ---------------------------------------------------------------- macOS

// spHardware/spSoftware/spApps model the parts of `system_profiler -json` we use.
type systemProfiler struct {
	Hardware []struct {
		MachineModel   string `json:"machine_model"`
		MachineName    string `json:"machine_name"`
		ModelNumber    string `json:"model_number"`
		Serial         string `json:"serial_number"`
		ChipType       string `json:"chip_type"`
		CPUType        string `json:"cpu_type"`
		CurrentSpeed   string `json:"current_processor_speed"`
		NumProcessors  any    `json:"number_processors"` // int (Intel) or "proc 10:8:2" (Apple silicon)
		PhysicalMemory string `json:"physical_memory"`
		BootROM        string `json:"boot_rom_version"`
	} `json:"SPHardwareDataType"`
	Software []struct {
		OSVersion     string `json:"os_version"`
		KernelVersion string `json:"kernel_version"`
	} `json:"SPSoftwareDataType"`
	Apps []struct {
		Name         string `json:"_name"`
		Version      string `json:"version"`
		ObtainedFrom string `json:"obtained_from"`
		LastModified string `json:"lastModified"`
		Info         string `json:"info"`
		Path         string `json:"path"`
		Arch         string `json:"arch_kind"`
	} `json:"SPApplicationsDataType"`
}

var (
	reMacOSVersion = regexp.MustCompile(`^(.*?)\s+([\d.]+)\s+\(([^)]+)\)`)
	reGB           = regexp.MustCompile(`^([\d.]+)\s*(GB|MB|TB)`)
	reGHz          = regexp.MustCompile(`([\d.,]+)\s*GHz`)
	reProc         = regexp.MustCompile(`proc\s+(\d+)`)
)

// applySystemProfiler maps system_profiler JSON onto the inventory.
func applySystemProfiler(data []byte, inv *Inventory) error {
	var p systemProfiler
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	inv.Hardware.Manufacturer = sp("Apple Inc.")
	if len(p.Hardware) > 0 {
		h := p.Hardware[0]
		model := h.MachineName
		if h.MachineModel != "" {
			model = strings.TrimSpace(h.MachineName + " (" + h.MachineModel + ")")
		}
		inv.Hardware.Model = sp(model)
		inv.Hardware.SerialNumber = sp(h.Serial)
		inv.Hardware.BiosVersion = sp(h.BootROM)
		inv.Hardware.BiosVendor = sp("Apple Inc.")
		cpu := h.ChipType
		if cpu == "" {
			cpu = h.CPUType
		}
		inv.Hardware.CPU.Model = sp(cpu)
		switch v := h.NumProcessors.(type) {
		case float64:
			inv.Hardware.CPU.Cores = fp(v)
		case string:
			if m := reProc.FindStringSubmatch(v); m != nil {
				n, _ := strconv.ParseFloat(m[1], 64)
				inv.Hardware.CPU.Cores = fp(n)
			}
		}
		if m := reGHz.FindStringSubmatch(h.CurrentSpeed); m != nil {
			ghz, _ := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", "."), 64)
			inv.Hardware.CPU.MHz = fp(math.Round(ghz * 1000))
		}
		inv.Hardware.MemoryBytes = fp(parseSize(h.PhysicalMemory))
	}
	if len(p.Software) > 0 {
		s := p.Software[0]
		if m := reMacOSVersion.FindStringSubmatch(s.OSVersion); m != nil {
			inv.OS.Name, inv.OS.Version, inv.OS.Build = sp(m[1]), sp(m[2]), sp(m[3])
		} else {
			inv.OS.Name = sp(s.OSVersion)
		}
		inv.OS.Kernel = sp(s.KernelVersion)
	}
	for _, a := range p.Apps {
		if a.Name == "" || strings.HasPrefix(a.Path, "/System/") {
			continue
		}
		var date *string
		if t, err := time.Parse(time.RFC3339, a.LastModified); err == nil {
			date = sp(t.UTC().Format("2006-01-02"))
		}
		inv.Software = append(inv.Software, Software{
			Name: a.Name, Version: a.Version, Publisher: appPublisher(a.ObtainedFrom, a.Info),
			InstallDate: date, Source: "app", Arch: a.Arch,
		})
	}
	return nil
}

func appPublisher(obtainedFrom, info string) string {
	switch obtainedFrom {
	case "apple":
		return "Apple Inc."
	}
	// "Copyright © 2024 Mozilla Corporation" → keep as is, trimmed
	return strings.TrimSpace(info)
}

// parseSize converts "16 GB" → bytes.
func parseSize(s string) float64 {
	m := reGB.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	switch m[2] {
	case "MB":
		return n * (1 << 20)
	case "GB":
		return n * (1 << 30)
	case "TB":
		return n * (1 << 40)
	}
	return 0
}

// parseDF parses `df -kP` (POSIX format, 1K blocks) and keeps real local volumes.
func parseDF(s string) []Disk {
	var out []Disk
	for i, l := range lines(s) {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(l)
		if len(f) < 6 || !strings.HasPrefix(f[0], "/dev/") {
			continue
		}
		mountPoint := strings.Join(f[5:], " ")
		if strings.HasPrefix(mountPoint, "/System/Volumes/") && mountPoint != "/System/Volumes/Data" {
			continue
		}
		total, _ := strconv.ParseFloat(f[1], 64)
		avail, _ := strconv.ParseFloat(f[3], 64)
		out = append(out, Disk{Name: f[0], Mount: sp(mountPoint), SizeBytes: fp(total * 1024), FreeBytes: fp(avail * 1024)})
	}
	return out
}

// parseLaunchctlList parses `launchctl list` (PID Status Label).
func parseLaunchctlList(s string) []Service {
	var out []Service
	for i, l := range lines(s) {
		if i == 0 && strings.HasPrefix(l, "PID") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		state := "stopped"
		if f[0] != "-" {
			state = "running"
		}
		out = append(out, Service{Name: f[2], State: sp(state), StartMode: sp("launchd")})
	}
	return out
}

// parseDsclUsers parses `dscl . -list /Users UniqueID`, skipping service accounts.
func parseDsclUsers(s string) []User {
	var out []User
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) < 2 || strings.HasPrefix(f[0], "_") {
			continue
		}
		uid, _ := strconv.Atoi(f[1])
		out = append(out, User{Name: f[0], UID: sp(f[1]), Disabled: bp(uid < 500 && uid != 0)})
	}
	return out
}

// parseDsclGroups parses `dscl . -list /Groups GroupMembership`.
func parseDsclGroups(s string) []Group {
	var out []Group
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "_") {
			continue
		}
		members := f[1:]
		if members == nil {
			members = []string{}
		}
		out = append(out, Group{Name: f[0], Members: members})
	}
	return out
}

// ---------------------------------------------------------------- Windows

// parseQuser parses `quser` output (header line is localised, so it is skipped by
// position). The current session is marked with a leading '>'.
//
//	 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
//	>administrator         rdp-tcp#0           2  Active          .  12.11.2026 08:00
//	 max                                       3  Disc            5  12.11.2026 07:00
func parseQuser(s string) []string {
	seen := map[string]bool{}
	var out []string
	for i, l := range lines(s) {
		if i == 0 {
			continue
		}
		f := strings.Fields(strings.TrimLeft(l, "> "))
		if len(f) == 0 {
			continue
		}
		u := f[0]
		if !seen[strings.ToLower(u)] {
			seen[strings.ToLower(u)] = true
			out = append(out, u)
		}
	}
	return out
}

// applyWindowsJSON merges the output of windows.ps1 into inv (network and
// collectedAt are filled in by Collect).
func applyWindowsJSON(data []byte, inv *Inventory) error {
	// PowerShell may emit a UTF-8 BOM.
	data = []byte(strings.TrimPrefix(string(data), "﻿"))
	var w Inventory
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	inv.Hardware, inv.OS = w.Hardware, w.OS
	inv.Disks, inv.Software, inv.Patches = w.Disks, w.Software, w.Patches
	inv.Services, inv.Autostart = w.Services, w.Autostart
	inv.LocalUsers, inv.LocalGroups, inv.LoggedOnUsers = w.LocalUsers, w.LocalGroups, w.LoggedOnUsers
	return nil
}
