package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func offer(priv ed25519.PrivateKey, body, version string) *Offer {
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, Message(OSName(), runtime.GOARCH, version, sha))
	return &Offer{Version: version, SHA256: sha, SizeBytes: int64(len(body)), Signature: base64.StdEncoding.EncodeToString(sig)}
}

func serve(body string) Download {
	return func(_ context.Context, w io.Writer) error {
		_, err := io.Copy(w, strings.NewReader(body))
		return err
	}
}

func TestApplyReplacesBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	exe := filepath.Join(t.TempDir(), "opencm-agent")
	if err := os.WriteFile(exe, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Apply(context.Background(), offer(priv, "NEW", "1.2.3"), pub, exe, serve("NEW"))
	if !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("expected restart, got %v", err)
	}
	b, _ := os.ReadFile(exe)
	if string(b) != "NEW" {
		t.Fatalf("binary not replaced: %q", b)
	}
	Cleanup(exe)
}

func TestApplyRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "opencm-agent")
	_ = os.WriteFile(exe, []byte("OLD"), 0o755)

	cases := map[string]struct {
		o    *Offer
		body string
	}{
		"foreign signature":   {offer(other, "NEW", "1"), "NEW"},
		"manipulated binary":  {offer(priv, "NEW", "1"), "EVIL"},
		"version swapped":     {func() *Offer { o := offer(priv, "NEW", "1"); o.Version = "2"; return o }(), "NEW"},
		"truncated signature": {func() *Offer { o := offer(priv, "NEW", "1"); o.Signature = "AAAA"; return o }(), "NEW"},
	}
	for name, c := range cases {
		if err := Apply(context.Background(), c.o, pub, exe, serve(c.body)); err == nil || errors.Is(err, ErrRestartRequired) {
			t.Errorf("%s: expected rejection, got %v", name, err)
		}
	}
	b, _ := os.ReadFile(exe)
	if string(b) != "OLD" {
		t.Fatalf("binary must stay untouched, got %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}
