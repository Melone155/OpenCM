package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func bv(b *bool) string {
	if b == nil {
		return "<nil>"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestParseDpkgSourceFields(t *testing.T) {
	in := "libxml2-utils\t2.9.13+dfsg-1ubuntu0.3\tUbuntu Developers <x@y>\tamd64\tii \tlibxml2\t2.9.13+dfsg-1ubuntu0.3\n" +
		"bash\t5.2.15-2+b2\tMatthias Klose <x@y>\tamd64\tii \tbash\t5.2.15-2\n"
	got := parseDpkg(in)
	if len(got) != 2 || deref(got[0].SourceName) != "libxml2" || deref(got[1].SourceVersion) != "5.2.15-2" || got[1].Version != "5.2.15-2+b2" {
		t.Fatalf("%#v", got)
	}
}

func TestParseRPMSourceFields(t *testing.T) {
	in := "openssl-libs\t3.0.7-27.el9\tRocky Enterprise Software Foundation\t1700000000\tx86_64\t1\topenssl-3.0.7-27.el9.src.rpm\n" +
		"sudo\t1.9.5p2-9.el9\tRocky\t1700000000\tx86_64\t(none)\tsudo-1.9.5p2-9.el9.src.rpm\n"
	got := parseRPM(in)
	if len(got) != 2 {
		t.Fatalf("len %d", len(got))
	}
	if deref(got[0].SourceName) != "openssl" || deref(got[0].SourceVersion) != "1:3.0.7-27.el9" || got[0].Version != "3.0.7-27.el9" {
		t.Fatalf("openssl: %#v", got[0])
	}
	if deref(got[1].SourceName) != "sudo" || deref(got[1].SourceVersion) != "1.9.5p2-9.el9" {
		t.Fatalf("sudo: %#v", got[1])
	}
	if srpmName("python3.11-requests-2.28.1-1.el9.src.rpm") != "python3.11-requests" || srpmName("(none)") != "" {
		t.Fatal("srpmName")
	}
}

const lsblkJSON = `{"blockdevices": [
  {"name":"nvme0n1","type":"disk","fstype":null,"mountpoint":null,"children":[
    {"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoint":"/boot/efi"},
    {"name":"nvme0n1p2","type":"part","fstype":"ext4","mountpoint":"/boot"},
    {"name":"nvme0n1p3","type":"part","fstype":"crypto_LUKS","mountpoint":null,"children":[
      {"name":"dm_crypt-0","type":"crypt","fstype":"LVM2_member","mountpoint":null,"children":[
        {"name":"vg-root","type":"lvm","fstype":"ext4","mountpoint":"/"},
        {"name":"vg-swap","type":"lvm","fstype":"swap","mountpoint":"[SWAP]"}
      ]}
    ]}
  ]},
  {"name":"sdb","type":"disk","fstype":null,"mountpoint":null,"children":[
    {"name":"sdb1","type":"part","fstype":"xfs","mountpoints":["/data"]}
  ]},
  {"name":"loop0","type":"loop","fstype":"squashfs","mountpoint":"/snap/core/1"}
]}`

func TestParseLsblk(t *testing.T) {
	vols := parseLsblk([]byte(lsblkJSON))
	if len(vols) != 2 {
		t.Fatalf("expected / and /data, got %#v", vols)
	}
	if vols[0].Volume != "/" || bv(vols[0].Encrypted) != "true" || bv(vols[0].System) != "true" {
		t.Fatalf("root: %#v", vols[0])
	}
	if vols[1].Volume != "/data" || bv(vols[1].Encrypted) != "false" {
		t.Fatalf("data: %#v", vols[1])
	}
	if parseLsblk([]byte("not json")) != nil {
		t.Fatal("invalid json")
	}
}

func TestParseFirewallAndBootLinux(t *testing.T) {
	if bv(parseUfwStatus("Status: active\n\nTo Action From\n")) != "true" || bv(parseUfwStatus("Status: inactive\n")) != "false" || parseUfwStatus("") != nil {
		t.Fatal("ufw")
	}
	if bv(parseFirewalldState("running\n")) != "true" || bv(parseFirewalldState("not running")) != "false" {
		t.Fatal("firewalld")
	}
	if !nftHasInputFilter("table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}") || nftHasInputFilter("") {
		t.Fatal("nft")
	}
	if bv(parseMokutil("SecureBoot enabled\n")) != "true" || bv(parseMokutil("SecureBoot disabled")) != "false" || parseMokutil("EFI variables are not supported") == nil {
		t.Fatal("mokutil")
	}
	if bv(parseSecureBootEFIVar([]byte{6, 0, 0, 0, 1})) != "true" || bv(parseSecureBootEFIVar([]byte{6, 0, 0, 0, 0})) != "false" || parseSecureBootEFIVar([]byte{1}) != nil {
		t.Fatal("efivar")
	}
	if bv(parseMdatpField("true\n")) != "true" || bv(parseMdatpField(`"false"`)) != "false" || parseMdatpField("unavailable") != nil {
		t.Fatal("mdatp")
	}
}

func TestParseMacOSSecurity(t *testing.T) {
	if enc, _ := parseFdesetup("FileVault is On.\n"); bv(enc) != "true" {
		t.Fatal("fdesetup on")
	}
	if enc, st := parseFdesetup("FileVault is Off.\n"); bv(enc) != "false" || st == "" {
		t.Fatal("fdesetup off")
	}
	if enc, _ := parseFdesetup("Encryption in progress: Percent completed = 42"); bv(enc) != "false" {
		t.Fatal("fdesetup progress")
	}
	if bv(parseSocketFilterFw("Firewall is enabled. (State = 1)")) != "true" || bv(parseSocketFilterFw("Firewall is disabled. (State = 0)")) != "false" {
		t.Fatal("socketfilterfw")
	}
	if bv(parseSpctlStatus("assessments enabled\n")) != "true" || bv(parseSpctlStatus("assessments disabled")) != "false" {
		t.Fatal("spctl")
	}
}

// Shape produced by windows_security.ps1 (synthetic values).
const windowsSecurityJSON = "\uFEFF" + `{"encryption":{"product":"BitLocker","volumes":[{"volume":"C:","system":true,"encrypted":true,"status":"FullyEncrypted","method":"XtsAes256","protection":true}]},
"antivirus":[{"name":"Microsoft Defender Antivirus","enabled":true,"realtime":true,"upToDate":null,"signatureVersion":"1.401.1.0","signatureUpdatedAt":"2026-11-12T06:00:00Z","lastScanAt":null}],
"firewall":{"product":"Windows Defender Firewall","enabled":null,"profiles":[{"name":"Domain","enabled":true},{"name":"Private","enabled":true},{"name":"Public","enabled":false}]},
"secureBoot":true,"tpm":{"present":true,"ready":true,"version":"2.0"}}`

func TestApplyWindowsSecurityJSON(t *testing.T) {
	s, err := applyWindowsSecurityJSON([]byte(windowsSecurityJSON))
	if err != nil {
		t.Fatal(err)
	}
	if deref(s.Encryption.Product) != "BitLocker" || bv(s.Encryption.Volumes[0].Protection) != "true" || len(s.Firewall.Profiles) != 3 || bv(s.SecureBoot) != "true" || deref(s.TPM.Version) != "2.0" {
		t.Fatalf("%#v", s)
	}
	// empty sections must serialise as [] (the server rejects null lists)
	empty, _ := applyWindowsSecurityJSON([]byte(`{"encryption":{"product":null,"volumes":null},"antivirus":null,"firewall":{},"secureBoot":null,"tpm":{}}`))
	b, _ := json.Marshal(empty)
	if !strings.Contains(string(b), `"volumes":[]`) || !strings.Contains(string(b), `"antivirus":[]`) || !strings.Contains(string(b), `"profiles":[]`) {
		t.Fatalf("normalize: %s", b)
	}
}

func TestSecurityScriptFitsCommandLine(t *testing.T) {
	if n := len(encodePowerShell(windowsSecurityScript)); n > 30000 {
		t.Fatalf("encoded security script too long: %d", n)
	}
	if !strings.Contains(windowsSecurityScript, "Win32_EncryptableVolume") || !strings.Contains(windowsSecurityScript, "Get-MpComputerStatus") {
		t.Fatal("embedded script incomplete")
	}
}

func TestInventoryOmitsSecurityWhenNil(t *testing.T) {
	inv := &Inventory{}
	inv.normalize()
	b, _ := json.Marshal(inv)
	if strings.Contains(string(b), `"security"`) {
		t.Fatalf("older servers must not see the field when nothing was collected: %s", b)
	}
}
