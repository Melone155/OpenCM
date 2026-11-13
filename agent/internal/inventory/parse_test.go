package inventory

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func TestParseOSRelease(t *testing.T) {
	m := parseOSRelease("# comment\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME='Ubuntu 24.04.1 LTS'\nID=ubuntu\n")
	if m["NAME"] != "Ubuntu" || m["VERSION_ID"] != "24.04" || m["PRETTY_NAME"] != "Ubuntu 24.04.1 LTS" || m["ID"] != "ubuntu" {
		t.Fatalf("unexpected: %#v", m)
	}
}

const cpuinfo = `processor	: 0
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
physical id	: 0
core id		: 0
cpu cores	: 2
cpu MHz		: 2399.998

processor	: 1
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
physical id	: 0
core id		: 1
cpu cores	: 2
cpu MHz		: 2399.998

processor	: 2
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
physical id	: 0
core id		: 0
cpu cores	: 2

processor	: 3
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
physical id	: 0
core id		: 1
cpu cores	: 2
`

func TestParseCPUInfo(t *testing.T) {
	model, cores, logical, mhz := parseCPUInfo(cpuinfo)
	if !strings.HasPrefix(model, "Intel(R) Xeon") || cores != 2 || logical != 4 || mhz < 2399 || mhz > 2400 {
		t.Fatalf("got %q cores=%d logical=%d mhz=%v", model, cores, logical, mhz)
	}
	// Raspberry Pi style (no physical id / cpu cores)
	_, cores, logical, _ = parseCPUInfo("processor\t: 0\nModel\t: Raspberry Pi 4\n\nprocessor\t: 1\n\n")
	if cores != 2 || logical != 2 {
		t.Fatalf("arm: cores=%d logical=%d", cores, logical)
	}
}

func TestParseMemAndBoot(t *testing.T) {
	if got := parseMemInfoTotal("MemTotal:       16314616 kB\nMemFree: 1 kB\n"); got != 16314616*1024 {
		t.Fatalf("mem %v", got)
	}
	if got := parseBootTime("cpu  1 2 3\nbtime 1700000000\n"); got != "2023-11-14T22:13:20Z" {
		t.Fatalf("boot %q", got)
	}
}

func TestParseDpkg(t *testing.T) {
	in := "openssl\t3.0.13-0ubuntu3.4\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\tamd64\tii \n" +
		"oldpkg\t1.0\tSomeone <a@b>\tall\trc \n" +
		"bash\t5.2.21-2ubuntu4\tUbuntu Developers <x@y>\tamd64\tii \n"
	got := parseDpkg(in)
	if len(got) != 2 || got[0].Name != "openssl" || got[0].Publisher != "Ubuntu Developers" || got[0].Source != "dpkg" || got[1].Arch != "amd64" {
		t.Fatalf("unexpected: %#v", got)
	}
}

func TestParseRPM(t *testing.T) {
	in := "openssl\t3.0.7-27.el9\tRed Hat, Inc.\t1700000000\tx86_64\n" +
		"gpg-pubkey\tfd431d51-4ae0493b\t(none)\t1700000000\t(none)\n" +
		"tzdata\t2024a-1.el9\t(none)\t0\tnoarch\n"
	got := parseRPM(in)
	if len(got) != 2 {
		t.Fatalf("len %d: %#v", len(got), got)
	}
	if got[0].Version != "3.0.7-27.el9" || got[0].Publisher != "Red Hat, Inc." || deref(got[0].InstallDate) != "2023-11-14" {
		t.Fatalf("openssl: %#v", got[0])
	}
	if got[1].Publisher != "" || got[1].InstallDate != nil {
		t.Fatalf("tzdata: %#v", got[1])
	}
}

func TestParseSystemdUnits(t *testing.T) {
	units := "ssh.service loaded active running OpenBSD Secure Shell server\n" +
		"● failed.service loaded failed failed Broken thing\n" +
		"cron.service loaded active running Regular background program processing daemon\n"
	files := "ssh.service enabled enabled\ncron.service enabled enabled\nfailed.service disabled enabled\nunused.service disabled enabled\ngetty@.service enabled enabled\n"
	got := parseSystemdUnits(units, files)
	byName := map[string]Service{}
	for _, s := range got {
		byName[s.Name] = s
	}
	if len(got) != 4 {
		t.Fatalf("len %d: %#v", len(got), got)
	}
	if deref(byName["ssh"].State) != "running" || deref(byName["ssh"].StartMode) != "enabled" || deref(byName["ssh"].DisplayName) != "OpenBSD Secure Shell server" {
		t.Fatalf("ssh: %#v", byName["ssh"])
	}
	if deref(byName["failed"].State) != "failed" {
		t.Fatalf("failed: %#v", byName["failed"])
	}
	if deref(byName["unused"].State) != "inactive" || deref(byName["unused"].StartMode) != "disabled" {
		t.Fatalf("unused: %#v", byName["unused"])
	}
}

func TestParsePasswdGroupWho(t *testing.T) {
	users := parsePasswd("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nmax:x:1000:1000:Max Muster,,,:/home/max:/bin/bash\n")
	if len(users) != 3 || *users[0].Disabled || !*users[1].Disabled || *users[2].Disabled || deref(users[2].FullName) != "Max Muster" {
		t.Fatalf("users: %#v", users)
	}
	groups := parseGroup("sudo:x:27:max,anna\nusers:x:100:\n")
	if len(groups) != 2 || len(groups[0].Members) != 2 || groups[1].Members == nil || len(groups[1].Members) != 0 {
		t.Fatalf("groups: %#v", groups)
	}
	who := parseWho("max      tty7         2026-11-12 08:00 (:0)\nmax      pts/0        2026-11-12 09:00\nanna     pts/1        2026-11-12 09:30 (10.0.0.5)\n")
	if strings.Join(who, ",") != "max,anna" {
		t.Fatalf("who: %v", who)
	}
}

func TestParseMounts(t *testing.T) {
	in := "/dev/sda2 / ext4 rw 0 0\nproc /proc proc rw 0 0\n/dev/sda1 /boot/efi vfat rw 0 0\n/dev/sda2 /var/snap ext4 rw 0 0\n" +
		"/dev/loop0 /snap/core/1 squashfs ro 0 0\n/dev/sdb1 /mnt/my\\040data xfs rw 0 0\noverlay /var/lib/docker/overlay2/x overlay rw 0 0\n"
	got := parseMounts(in)
	if len(got) != 3 || got[0].point != "/" || got[1].point != "/boot/efi" || got[2].point != "/mnt/my data" {
		t.Fatalf("%#v", got)
	}
}

func TestParseDesktopEntry(t *testing.T) {
	name, exec, hidden := parseDesktopEntry("[Desktop Entry]\nName=Nextcloud\nExec=/usr/bin/nextcloud --background\n[Desktop Action x]\nExec=other\n")
	if name != "Nextcloud" || exec != "/usr/bin/nextcloud --background" || hidden {
		t.Fatalf("%q %q %v", name, exec, hidden)
	}
}

const systemProfilerJSON = `{
 "SPHardwareDataType": [{"machine_model":"Mac14,2","machine_name":"MacBook Air","serial_number":"C02TEST123",
   "chip_type":"Apple M2","number_processors":"proc 8:4:4","physical_memory":"16 GB","boot_rom_version":"10151.1.1"}],
 "SPSoftwareDataType": [{"os_version":"macOS 14.5 (23F79)","kernel_version":"Darwin 23.5.0"}],
 "SPApplicationsDataType": [
   {"_name":"Firefox","version":"131.0","obtained_from":"identified_developer","lastModified":"2025-10-01T10:00:00Z","info":"Firefox 131.0","path":"/Applications/Firefox.app","arch_kind":"arch_arm_i64"},
   {"_name":"Safari","version":"17.5","obtained_from":"apple","path":"/Applications/Safari.app"},
   {"_name":"Ticket Viewer","version":"4.0","obtained_from":"apple","path":"/System/Library/CoreServices/Ticket Viewer.app"}
 ]}`

func TestApplySystemProfiler(t *testing.T) {
	inv := &Inventory{}
	if err := applySystemProfiler([]byte(systemProfilerJSON), inv); err != nil {
		t.Fatal(err)
	}
	h := inv.Hardware
	if deref(h.Model) != "MacBook Air (Mac14,2)" || deref(h.SerialNumber) != "C02TEST123" || deref(h.CPU.Model) != "Apple M2" {
		t.Fatalf("hw: %#v", h)
	}
	if h.CPU.Cores == nil || *h.CPU.Cores != 8 || h.MemoryBytes == nil || *h.MemoryBytes != 16*(1<<30) {
		t.Fatalf("cpu/mem: %v %v", h.CPU.Cores, h.MemoryBytes)
	}
	if deref(inv.OS.Name) != "macOS" || deref(inv.OS.Version) != "14.5" || deref(inv.OS.Build) != "23F79" {
		t.Fatalf("os: %#v", inv.OS)
	}
	if len(inv.Software) != 2 || inv.Software[0].Name != "Firefox" || deref(inv.Software[0].InstallDate) != "2025-10-01" || inv.Software[1].Publisher != "Apple Inc." {
		t.Fatalf("apps: %#v", inv.Software)
	}
	// Intel Macs report number_processors as a number
	inv2 := &Inventory{}
	_ = applySystemProfiler([]byte(`{"SPHardwareDataType":[{"cpu_type":"Quad-Core Intel Core i7","number_processors":4,"current_processor_speed":"2,3 GHz"}]}`), inv2)
	if inv2.Hardware.CPU.Cores == nil || *inv2.Hardware.CPU.Cores != 4 || inv2.Hardware.CPU.MHz == nil || *inv2.Hardware.CPU.MHz != 2300 {
		t.Fatalf("intel: %v %v", inv2.Hardware.CPU.Cores, inv2.Hardware.CPU.MHz)
	}
}

func TestParseMacOSCommands(t *testing.T) {
	df := "Filesystem     1024-blocks      Used Available Capacity  Mounted on\n" +
		"/dev/disk3s1s1   482797652  10000000 300000000     4%    /\n" +
		"devfs                  200       200         0   100%    /dev\n" +
		"/dev/disk3s6     482797652   2000000 300000000     1%    /System/Volumes/VM\n" +
		"/dev/disk3s5     482797652 150000000 300000000    34%    /System/Volumes/Data\n" +
		"/dev/disk4s1        100000     50000     50000    50%    /Volumes/USB Stick\n"
	disks := parseDF(df)
	if len(disks) != 3 || deref(disks[2].Mount) != "/Volumes/USB Stick" || *disks[0].SizeBytes != 482797652*1024 {
		t.Fatalf("df: %#v", disks)
	}
	svcs := parseLaunchctlList("PID\tStatus\tLabel\n123\t0\tcom.apple.Finder\n-\t0\torg.example.idle\n")
	if len(svcs) != 2 || deref(svcs[0].State) != "running" || deref(svcs[1].State) != "stopped" {
		t.Fatalf("launchctl: %#v", svcs)
	}
	users := parseDsclUsers("_spotlight 89\ndaemon 1\nroot 0\nmax 501\n")
	if len(users) != 3 || !*users[0].Disabled || *users[1].Disabled || *users[2].Disabled {
		t.Fatalf("dscl users: %#v", users)
	}
	groups := parseDsclGroups("_appserveradm\nadmin root max\nstaff\n")
	if len(groups) != 2 || len(groups[0].Members) != 2 || groups[1].Members == nil {
		t.Fatalf("dscl groups: %#v", groups)
	}
}

// Shape produced by windows.ps1 (synthetic values).
const windowsJSON = "\ufeff" + `{"hardware":{"manufacturer":"Contoso","model":"Workstation 5000","serialNumber":"SN1","chassis":"Desktop",
"biosVendor":"Contoso","biosVersion":"1.2","biosDate":"2024-01-01T00:00:00Z","cpu":{"model":"Example CPU","cores":8,"logicalProcessors":16,"mhz":3200},
"memoryBytes":34359738368},"os":{"name":"Microsoft Windows 11 Pro","version":"23H2 (10.0.22631)","build":"22631.4460","arch":"64-Bit",
"kernel":"10.0.22631","installDate":"2025-01-01T00:00:00Z","lastBoot":"2026-11-12T06:00:00Z"},
"disks":[{"name":"C:","mount":"C:\\","fsType":"NTFS","sizeBytes":512000000000,"freeBytes":100000000000}],
"software":[{"name":"7-Zip 23.01 (x64)","version":"23.01","publisher":"Igor Pavlov","installDate":"2025-03-01","source":"registry","arch":"x64"}],
"patches":[{"id":"KB5031455","description":"Update","installedOn":"2025-10-10T00:00:00Z"}],
"services":[{"name":"Spooler","displayName":"Druckwarteschlange","state":"Running","startMode":"Auto"}],
"autostart":[],"localUsers":[{"name":"Administrator","fullName":null,"disabled":true,"uid":"S-1-5-21-1-500"}],
"localGroups":[{"name":"Administratoren","members":["PC1\\Administrator","CONTOSO\\Domänen-Admins"]}],"loggedOnUsers":["CONTOSO\\max"]}`

func TestApplyWindowsJSON(t *testing.T) {
	inv := &Inventory{}
	if err := applyWindowsJSON([]byte(windowsJSON), inv); err != nil {
		t.Fatal(err)
	}
	if deref(inv.Hardware.Model) != "Workstation 5000" || *inv.Hardware.CPU.Cores != 8 || len(inv.Software) != 1 || inv.LocalGroups[0].Members[1] != `CONTOSO\Domänen-Admins` {
		t.Fatalf("%#v", inv)
	}
	inv.normalize()
	b, _ := json.Marshal(inv)
	if !strings.Contains(string(b), `"network":[]`) || !strings.Contains(string(b), `"autostart":[]`) {
		t.Fatalf("normalize: %s", b)
	}
}

func TestParseQuser(t *testing.T) {
	out := " BENUTZERNAME          SITZUNGSNAME       ID  STATUS  LEERLAUF   ANMELDEZEIT\r\n" +
		">administrator         rdp-tcp#0           2  Aktiv          .  12.11.2026 08:00\r\n" +
		" max                                       3  Getr.          5  12.11.2026 07:00\r\n" +
		" MAX                   console             4  Aktiv       none  12.11.2026 07:30\r\n"
	got := parseQuser(out)
	if strings.Join(got, ",") != "administrator,max" {
		t.Fatalf("got %v", got)
	}
	if len(parseQuser("")) != 0 {
		t.Fatal("empty output")
	}
}

func TestEncodePowerShellFitsCommandLine(t *testing.T) {
	enc := encodePowerShell(windowsScript)
	if len(enc) > 30000 {
		t.Fatalf("encoded script too long for the Windows command line: %d chars", len(enc))
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw)%2 != 0 {
		t.Fatal("not UTF-16LE base64")
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if string(utf16.Decode(u)) != windowsScript {
		t.Fatal("round trip mismatch")
	}
}
