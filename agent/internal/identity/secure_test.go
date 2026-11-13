package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// REV-006: configuration and key material that another user owns or can write must be refused.
func TestAssertTrustedAndPrepareConfigDir(t *testing.T) {
	base := t.TempDir()

	// a missing path is skipped, a freshly created directory is trusted
	if err := AssertTrusted(filepath.Join(base, "missing")); err != nil {
		t.Fatalf("missing path must be skipped: %v", err)
	}
	dir := filepath.Join(base, "OpenCM")
	trusted, err := PrepareConfigDir(dir)
	if runtime.GOOS == "windows" && err != nil {
		t.Skipf("needs an elevated process to take ownership: %v", err)
	}
	if err != nil || !trusted {
		t.Fatalf("new config dir: trusted=%v err=%v", trusted, err)
	}
	if err := AssertTrusted(dir); err != nil {
		t.Fatalf("prepared dir must be trusted: %v", err)
	}

	if runtime.GOOS == "windows" {
		return // foreign ownership cannot be simulated without a second account
	}
	// writable by others → not trusted, and enroll must not silently accept it
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := AssertTrusted(open); err == nil {
		t.Fatal("world-writable directory must not be trusted")
	}
	if trusted, err := PrepareConfigDir(open); trusted || err == nil {
		t.Fatalf("world-writable config dir must be refused: trusted=%v err=%v", trusted, err)
	}
}
