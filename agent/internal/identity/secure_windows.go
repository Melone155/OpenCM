//go:build windows

package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func icacls(args ...string) error {
	bin := "icacls.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		bin = filepath.Join(root, "System32", "icacls.exe")
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %v: %w: %s", args, err, out)
	}
	return nil
}

// secureDir makes dir and everything below it accessible to SYSTEM and Administrators only.
//
// ProgramData lets every user create sub-directories. A user who created the directory
// before the agent was installed stays its owner and could re-grant himself access at any
// time (and with it replace the agent's key, CA, signing key and endpoint – code execution
// as SYSTEM). Therefore, in this order:
//  1. take ownership of the whole tree for BUILTIN\Administrators,
//  2. drop every explicit ACE in the tree (only inherited ones remain),
//  3. cut the inheritance of dir and grant full control to SYSTEM and Administrators only;
//     the children inherit exactly that.
func secureDir(dir string) error {
	if err := icacls(dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"); err != nil {
		return err
	}
	if err := icacls(dir, "/reset", "/T", "/C", "/Q"); err != nil {
		return err
	}
	return icacls(dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", // BUILTIN\Administrators
	)
}

// OwnerTrusted reports whether path is owned by SYSTEM or BUILTIN\Administrators.
func OwnerTrusted(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil {
		return false, nil
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), nil
}

// hardenConfigDir repairs ownership and ACL of the configuration directory.
func hardenConfigDir(dir string, _ bool) error { return secureDir(dir) }
