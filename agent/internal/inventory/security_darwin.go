//go:build darwin

package inventory

import (
	"context"
	"os"
	"strings"
	"time"
)

const xprotectPlist = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"

// collectSecurityDarwin: FileVault, application firewall, XProtect/Gatekeeper.
// Secure Boot and the Secure Enclave are not readable without user interaction → unknown.
func collectSecurityDarwin(ctx context.Context) *Security {
	s := &Security{}
	if out, err := run(ctx, 15*time.Second, "/usr/bin/fdesetup", "status"); err == nil {
		if enc, status := parseFdesetup(out); enc != nil {
			s.Encryption = Encryption{Product: sp("FileVault"), Volumes: []Volume{{Volume: "/", System: bp(true), Encrypted: enc, Status: sp(status)}}}
		}
	}
	if out, err := run(ctx, 15*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		s.Firewall = Firewall{Product: sp("macOS-Firewall"), Enabled: parseSocketFilterFw(out)}
	}
	av := Antivirus{Name: "XProtect", Realtime: bp(true)}
	if out, err := run(ctx, 10*time.Second, "/usr/sbin/spctl", "--status"); err == nil {
		av.Enabled = parseSpctlStatus(out)
	}
	if out, err := run(ctx, 10*time.Second, "/usr/bin/defaults", "read", strings.TrimSuffix(xprotectPlist, ".plist"), "CFBundleShortVersionString"); err == nil {
		av.SignatureVersion = sp(strings.TrimSpace(out))
	}
	if st, err := os.Stat(xprotectPlist); err == nil {
		av.SignatureUpdatedAt = sp(st.ModTime().UTC().Format(time.RFC3339))
		s.Antivirus = append(s.Antivirus, av)
	}
	s.normalize()
	return s
}
