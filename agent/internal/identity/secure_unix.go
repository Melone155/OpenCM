//go:build !windows

package identity

import (
	"fmt"
	"os"
	"syscall"
)

func secureDir(dir string) error { return os.Chmod(dir, 0o700) }

// OwnerTrusted reports whether path belongs to root or to the user the agent runs as and
// is not writable by group or others.
func OwnerTrusted(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return false, nil
	}
	return fi.Mode().Perm()&0o022 == 0, nil
}

// hardenConfigDir: /etc and /Library are root-only, so a foreign or world-writable
// configuration directory is not repaired but refused.
func hardenConfigDir(dir string, trustedBefore bool) error {
	if !trustedBefore {
		return fmt.Errorf("%s is owned by another user or writable by others – remove it and enroll again", dir)
	}
	return nil
}
