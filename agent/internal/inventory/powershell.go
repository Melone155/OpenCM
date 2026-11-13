package inventory

import (
	_ "embed"
	"encoding/base64"
	"unicode/utf16"
)

//go:embed windows.ps1
var windowsScript string

// windowsSecurityScript collects the security posture (BitLocker, Defender, firewall, Secure Boot, TPM).
//
//go:embed windows_security.ps1
var windowsSecurityScript string

// encodePowerShell encodes a script for `powershell.exe -EncodedCommand`
// (base64 of UTF-16LE). Avoids temp files and quoting issues.
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
