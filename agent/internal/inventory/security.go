package inventory

// OS-neutral parsers for the security posture (disk encryption, firewall, antivirus).
// The collectors in security_<os>.go only run the commands; everything that interprets
// output lives here so it is unit tested on every CI platform.

import (
	"encoding/json"
	"strings"
)

// ---------------------------------------------------------------- Linux

type lsblkDev struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	FSType      *string    `json:"fstype"`
	Mountpoint  *string    `json:"mountpoint"`
	Mountpoints []*string  `json:"mountpoints"`
	Children    []lsblkDev `json:"children"`
}

// mountpoints that do not need encryption (ESP/boot partitions, swap handled separately)
var unencryptedOK = map[string]bool{"/boot": true, "/boot/efi": true, "/efi": true}

// parseLsblk parses `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINT` (util-linux; newer versions
// also emit MOUNTPOINTS). A mounted filesystem counts as encrypted when one of its
// ancestors is a dm-crypt device (TYPE "crypt", i.e. LUKS).
func parseLsblk(data []byte) []Volume {
	var doc struct {
		Blockdevices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []Volume
	seen := map[string]bool{}
	var walk func(d lsblkDev, crypt bool)
	walk = func(d lsblkDev, crypt bool) {
		crypt = crypt || d.Type == "crypt"
		mps := d.Mountpoints
		if d.Mountpoint != nil {
			mps = append(mps, d.Mountpoint)
		}
		for _, mp := range mps {
			if mp == nil || *mp == "" || seen[*mp] || unencryptedOK[*mp] || strings.HasPrefix(*mp, "[") || strings.HasPrefix(*mp, "/snap/") {
				continue
			}
			if d.Type == "rom" || d.Type == "loop" {
				continue
			}
			if d.FSType != nil && (*d.FSType == "swap" || *d.FSType == "squashfs" || *d.FSType == "iso9660") {
				continue
			}
			seen[*mp] = true
			enc := crypt
			sys := *mp == "/"
			status := "unencrypted"
			if enc {
				status = "LUKS"
			}
			out = append(out, Volume{Volume: *mp, System: bp(sys), Encrypted: bp(enc), Status: sp(status)})
		}
		for _, c := range d.Children {
			walk(c, crypt)
		}
	}
	for _, d := range doc.Blockdevices {
		walk(d, false)
	}
	return out
}

// parseUfwStatus: "Status: active" / "Status: inactive".
func parseUfwStatus(s string) *bool {
	for _, l := range lines(s) {
		l = strings.ToLower(strings.TrimSpace(l))
		if strings.HasPrefix(l, "status:") {
			return bp(strings.Contains(l, "active") && !strings.Contains(l, "inactive"))
		}
	}
	return nil
}

// parseFirewalldState: `firewall-cmd --state` → "running" / "not running".
func parseFirewalldState(s string) *bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	return bp(s == "running")
}

// nftHasInputFilter: an nftables ruleset with a base chain on the input hook counts as a firewall.
func nftHasInputFilter(ruleset string) bool {
	return strings.Contains(ruleset, "hook input")
}

// parseMokutil: "SecureBoot enabled" / "SecureBoot disabled" / "This system doesn't support Secure Boot".
func parseMokutil(s string) *bool {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "secureboot enabled"):
		return bp(true)
	case strings.Contains(l, "secureboot disabled"), strings.Contains(l, "doesn't support"), strings.Contains(l, "not supported"):
		return bp(false)
	}
	return nil
}

// parseSecureBootEFIVar: the SecureBoot efivar is 4 attribute bytes + 1 value byte.
func parseSecureBootEFIVar(b []byte) *bool {
	if len(b) < 5 {
		return nil
	}
	return bp(b[4] == 1)
}

// parseMdatpField: `mdatp health --field <name>` prints true/false (possibly quoted).
func parseMdatpField(s string) *bool {
	switch strings.Trim(strings.ToLower(strings.TrimSpace(s)), `"`) {
	case "true":
		return bp(true)
	case "false":
		return bp(false)
	}
	return nil
}

// ---------------------------------------------------------------- macOS

// parseFdesetup: "FileVault is On." / "FileVault is Off." / "Encryption in progress: …".
func parseFdesetup(s string) (encrypted *bool, status string) {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "filevault is on"):
		return bp(true), "FileVault an"
	case strings.Contains(l, "encryption in progress"):
		return bp(false), "Verschlüsselung läuft"
	case strings.Contains(l, "decryption in progress"):
		return bp(false), "Entschlüsselung läuft"
	case strings.Contains(l, "filevault is off"):
		return bp(false), "FileVault aus"
	}
	return nil, ""
}

// parseSocketFilterFw: "Firewall is enabled. (State = 1)" / "Firewall is disabled. (State = 0)".
func parseSocketFilterFw(s string) *bool {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "enabled"), strings.Contains(l, "state = 1"), strings.Contains(l, "state = 2"):
		return bp(true)
	case strings.Contains(l, "disabled"), strings.Contains(l, "state = 0"):
		return bp(false)
	}
	return nil
}

// parseSpctlStatus: "assessments enabled" / "assessments disabled" (Gatekeeper).
func parseSpctlStatus(s string) *bool {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "assessments enabled"):
		return bp(true)
	case strings.Contains(l, "assessments disabled"):
		return bp(false)
	}
	return nil
}

// ---------------------------------------------------------------- Windows

// applyWindowsSecurityJSON parses the output of windows_security.ps1.
func applyWindowsSecurityJSON(data []byte) (*Security, error) {
	data = []byte(strings.TrimPrefix(string(data), "﻿"))
	var s Security
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	s.normalize()
	return &s, nil
}
