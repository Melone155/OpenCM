//go:build linux

package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const secureBootVar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// collectSecurityLinux: LUKS (lsblk), ufw / firewalld / nftables, Secure Boot, TPM,
// Microsoft Defender for Endpoint (mdatp) and ClamAV. Best effort – missing tools leave
// the corresponding value unknown (nil).
func collectSecurityLinux(ctx context.Context) *Security {
	s := &Security{}

	// disk encryption
	if out, err := run(ctx, 20*time.Second, "lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"); err == nil {
		s.Encryption.Volumes = parseLsblk([]byte(out))
		for _, v := range s.Encryption.Volumes {
			if v.Encrypted != nil && *v.Encrypted {
				s.Encryption.Product = sp("LUKS")
				break
			}
		}
	}

	// firewall: ufw → firewalld → nftables
	if _, err := exec.LookPath("ufw"); err == nil {
		out, _ := run(ctx, 15*time.Second, "ufw", "status")
		if v := parseUfwStatus(out); v != nil {
			s.Firewall = Firewall{Product: sp("ufw"), Enabled: v}
		}
	}
	if s.Firewall.Enabled == nil || !*s.Firewall.Enabled {
		if _, err := exec.LookPath("firewall-cmd"); err == nil {
			out, _ := run(ctx, 15*time.Second, "firewall-cmd", "--state")
			if v := parseFirewalldState(out); v != nil && (s.Firewall.Enabled == nil || *v) {
				s.Firewall = Firewall{Product: sp("firewalld"), Enabled: v}
			}
		}
	}
	if s.Firewall.Enabled == nil || !*s.Firewall.Enabled {
		if _, err := exec.LookPath("nft"); err == nil {
			if out, err := run(ctx, 15*time.Second, "nft", "list", "ruleset"); err == nil {
				if nftHasInputFilter(out) {
					s.Firewall = Firewall{Product: sp("nftables"), Enabled: bp(true)}
				} else if s.Firewall.Enabled == nil {
					s.Firewall = Firewall{Product: sp("nftables"), Enabled: bp(false)}
				}
			}
		}
	}

	// Secure Boot
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		s.SecureBoot = bp(false) // legacy BIOS boot
	} else if b, err := os.ReadFile(secureBootVar); err == nil {
		s.SecureBoot = parseSecureBootEFIVar(b)
	} else if _, err := exec.LookPath("mokutil"); err == nil {
		out, _ := run(ctx, 10*time.Second, "mokutil", "--sb-state")
		s.SecureBoot = parseMokutil(out)
	}

	// TPM
	if _, err := os.Stat("/sys/class/tpm/tpm0"); err == nil {
		s.TPM = TPM{Present: bp(true), Ready: bp(true), Version: sp(readFile("/sys/class/tpm/tpm0/tpm_version_major"))}
		if s.TPM.Version != nil {
			v := *s.TPM.Version + ".0"
			s.TPM.Version = &v
		}
	} else if _, err := os.Stat("/sys/class/tpm"); err == nil {
		s.TPM = TPM{Present: bp(false)}
	}

	// antivirus (optional on Linux)
	if _, err := exec.LookPath("mdatp"); err == nil {
		field := func(name string) *bool {
			out, _ := run(ctx, 20*time.Second, "mdatp", "health", "--field", name)
			return parseMdatpField(out)
		}
		av := Antivirus{Name: "Microsoft Defender for Endpoint", Enabled: field("healthy"), Realtime: field("real_time_protection_enabled")}
		if st, _ := run(ctx, 20*time.Second, "mdatp", "health", "--field", "definitions_status"); strings.TrimSpace(st) != "" {
			av.UpToDate = bp(strings.Contains(strings.ToLower(st), "up_to_date"))
		}
		s.Antivirus = append(s.Antivirus, av)
	}
	if clam := clamav(ctx); clam != nil {
		s.Antivirus = append(s.Antivirus, *clam)
	}
	s.normalize()
	return s
}

func clamav(ctx context.Context) *Antivirus {
	_, e1 := exec.LookPath("clamd")
	_, e2 := exec.LookPath("clamdscan")
	if e1 != nil && e2 != nil {
		return nil
	}
	av := &Antivirus{Name: "ClamAV"}
	for _, unit := range []string{"clamav-daemon", "clamd@scan", "clamd"} {
		out, _ := run(ctx, 10*time.Second, "systemctl", "is-active", unit)
		if strings.TrimSpace(out) == "active" {
			av.Enabled = bp(true)
			break
		}
	}
	if av.Enabled == nil {
		av.Enabled = bp(false)
	}
	// signature age: newest daily database
	var newest time.Time
	matches, _ := filepath.Glob("/var/lib/clamav/daily.c?d") // .cld (incremental) or .cvd
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	if !newest.IsZero() {
		av.SignatureUpdatedAt = sp(newest.UTC().Format(time.RFC3339))
	}
	return av
}
