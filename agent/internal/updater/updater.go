// Package updater replaces the agent binary with a server-provided version after
// verifying its SHA-256 and the server's Ed25519 signature.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type Offer struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Signature string `json:"signature"`
}

// ErrRestartRequired signals that the new binary is in place and the process must restart.
var ErrRestartRequired = errors.New("agent updated – restart required")

// OSName maps GOOS to the server's OS names.
func OSName() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

// Message is what the server signs (must match server/src/pki/signing.ts → updateMessage).
func Message(os, arch, version, sha string) []byte {
	return []byte(fmt.Sprintf("opencm-agent-update:v1:%s:%s:%s:%s", os, arch, version, sha))
}

// VerifyOffer checks the signature before anything is downloaded.
func VerifyOffer(o *Offer, pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(o.Signature)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("update: malformed signature or missing key")
	}
	if !ed25519.Verify(pub, Message(OSName(), runtime.GOARCH, o.Version, o.SHA256), sig) {
		return errors.New("update: signature does not match – refusing update")
	}
	return nil
}

// Download fetches the binary (download writes to w).
type Download func(ctx context.Context, w io.Writer) error

// Apply verifies the offer, downloads the binary next to exe, checks hash and size
// and swaps it in. Returns ErrRestartRequired on success.
func Apply(ctx context.Context, o *Offer, pub ed25519.PublicKey, exe string, download Download) error {
	if err := VerifyOffer(o, pub); err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".opencm-agent-update-*")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(tmp, h)}
	if err := download(ctx, cw); err != nil {
		tmp.Close()
		return fmt.Errorf("update: download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != o.SHA256 {
		return fmt.Errorf("update: checksum mismatch (got %s)", got)
	}
	if o.SizeBytes > 0 && cw.n != o.SizeBytes {
		return fmt.Errorf("update: size mismatch (got %d, want %d)", cw.n, o.SizeBytes)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	if err := swap(exe, tmpName); err != nil {
		return fmt.Errorf("update: replace binary: %w", err)
	}
	return ErrRestartRequired
}

// swap replaces exe by next. Windows cannot overwrite a running executable but can
// rename it, so the old binary is moved aside first (removed on next start).
func swap(exe, next string) error {
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return err
		}
		if err := os.Rename(next, exe); err != nil {
			_ = os.Rename(old, exe) // roll back
			return err
		}
		return nil
	}
	return os.Rename(next, exe) // atomic on Unix; the running process keeps its inode
}

// Cleanup removes a leftover binary from a previous update (Windows).
func Cleanup(exe string) { _ = os.Remove(exe + ".old") }

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
