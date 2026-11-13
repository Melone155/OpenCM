package tasks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func shellInterpreter() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "bash"
}

func sign(t *testing.T, priv ed25519.PrivateKey, p Payload) *Envelope {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &Envelope{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))}
}

func payload(content string) Payload {
	return Payload{
		V: 1, TaskID: "task-1", DeviceID: "dev-1", Attempt: 1, ExpiresAt: time.Now().Add(10 * time.Minute), TimeoutSeconds: 30, StopOnError: true,
		Steps: []Step{{Position: 0, Interpreter: shellInterpreter(), Content: content, SHA256: hash(content)}},
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	if _, err := Verify(sign(t, priv, payload("echo ok")), pub, "dev-1", now); err != nil {
		t.Fatalf("valid task rejected: %v", err)
	}
	cases := map[string]func() (*Envelope, string){
		"foreign key":      func() (*Envelope, string) { return sign(t, otherPriv, payload("echo")), "dev-1" },
		"other device":     func() (*Envelope, string) { return sign(t, priv, payload("echo")), "dev-2" },
		"expired":          func() (*Envelope, string) { p := payload("echo"); p.ExpiresAt = now.Add(-time.Hour); return sign(t, priv, p), "dev-1" },
		"hash mismatch":    func() (*Envelope, string) { p := payload("echo"); p.Steps[0].Content = "rm -rf /"; return sign(t, priv, p), "dev-1" },
		"wrong version":    func() (*Envelope, string) { p := payload("echo"); p.V = 3; return sign(t, priv, p), "dev-1" },
		"files in v1": func() (*Envelope, string) {
			p := payload("echo")
			p.Steps[0].Files = []File{{SHA256: hash("x"), Name: "a.msi"}}
			return sign(t, priv, p), "dev-1"
		},
		"bad file hash": func() (*Envelope, string) {
			p := payload("echo")
			p.V = 2
			p.Steps[0].Files = []File{{SHA256: "../../etc/passwd", Name: "a"}}
			return sign(t, priv, p), "dev-1"
		},
		"bad interpreter":  func() (*Envelope, string) { p := payload("x"); p.Steps[0].Interpreter = "perl"; return sign(t, priv, p), "dev-1" },
		"no steps":         func() (*Envelope, string) { p := payload("x"); p.Steps = nil; return sign(t, priv, p), "dev-1" },
		"tampered payload": func() (*Envelope, string) {
			env := sign(t, priv, payload("echo"))
			raw, _ := base64.StdEncoding.DecodeString(env.Payload)
			env.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), "dev-1", "dev-1", 1) + " "))
			return env, "dev-1"
		},
	}
	for name, mk := range cases {
		env, dev := mk()
		if _, err := Verify(env, pub, dev, now); !errors.Is(err, ErrVerification) {
			t.Errorf("%s: expected verification error, got %v", name, err)
		}
	}
	if _, err := Verify(sign(t, priv, payload("echo")), nil, "dev-1", now); err == nil {
		t.Error("missing key must be rejected")
	}
	// hash and signature errors are marked as integrity violations
	p := payload("echo")
	p.Steps[0].Content = "rm -rf /"
	if _, err := Verify(sign(t, priv, p), pub, "dev-1", now); err == nil || !strings.Contains(err.Error(), IntegrityPrefix) {
		t.Errorf("hash mismatch must carry %q: %v", IntegrityPrefix, err)
	}
	if _, err := Verify(sign(t, otherPriv, payload("echo")), pub, "dev-1", now); err == nil || !strings.Contains(err.Error(), IntegrityPrefix) {
		t.Errorf("signature mismatch must carry %q: %v", IntegrityPrefix, err)
	}
	v2 := payload("echo")
	v2.V = 2
	v2.Steps[0].Files = []File{{SHA256: hash("x"), Name: "setup.msi", SizeBytes: 1}}
	if _, err := Verify(sign(t, priv, v2), pub, "dev-1", now); err != nil {
		t.Errorf("v2 with files rejected: %v", err)
	}
}

func filePayload(content string, data string) Payload {
	p := payload(content)
	p.V = 2
	p.Steps[0].Files = []File{{SHA256: hash(data), Name: "../evil name.msi", SizeBytes: int64(len(data))}}
	return p
}

func serve(data string) Downloader {
	return func(_ context.Context, _ string, w io.Writer) error {
		_, err := io.WriteString(w, data)
		return err
	}
}

func TestExecuteDownloadsAndVerifiesFiles(t *testing.T) {
	c := &collector{}
	e := &Executor{WorkDir: t.TempDir(), Report: c.report, Download: serve("installer-bytes")}
	content := script("cat \"$OPENCM_FILE_1\"", "@type \"%OPENCM_FILE_1%\"")
	p := filePayload(content, "installer-bytes")
	res := e.Run(context.Background(), &p)
	if res.Status != "succeeded" || res.Error != nil {
		t.Fatalf("result: %+v stderr=%q", res, c.text("stderr"))
	}
	if !strings.Contains(c.text("stdout"), "installer-bytes") {
		t.Fatalf("file not passed to the script: %q", c.text("stdout"))
	}
	if entries, _ := os.ReadDir(e.WorkDir); len(entries) != 0 {
		t.Fatalf("work dir not cleaned up: %v", entries)
	}
}

func TestExecuteAbortsOnFileHashMismatch(t *testing.T) {
	c := &collector{}
	e := &Executor{WorkDir: t.TempDir(), Report: c.report, Download: serve("TAMPERED")}
	marker := filepath.Join(t.TempDir(), "ran")
	content := script("touch '"+marker+"'", "@type nul > \""+marker+"\"")
	p := filePayload(content, "installer-bytes")
	ok := script("echo second", "@echo second")
	p.Steps = append(p.Steps, Step{Position: 1, Interpreter: shellInterpreter(), Content: ok, SHA256: hash(ok)})
	res := e.Run(context.Background(), &p)
	if res.Status != "failed" || res.Error == nil || !strings.HasPrefix(*res.Error, IntegrityPrefix) {
		t.Fatalf("expected integrity failure, got %+v", res)
	}
	if res.Steps[1].Status != "skipped" {
		t.Fatalf("following steps must not run: %+v", res.Steps)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the script ran despite the wrong file hash")
	}
	if !strings.Contains(c.text("stderr"), "Hash-Prüfung fehlgeschlagen") {
		t.Fatalf("not visible in the output: %q", c.text("stderr"))
	}
}

func TestExecuteAbortsOnTamperedContent(t *testing.T) {
	e := &Executor{WorkDir: t.TempDir(), Report: (&collector{}).report}
	p := payload(script("echo ok", "@echo ok"))
	p.Steps[0].Content = script("echo evil", "@echo evil") // changed after verification
	res := e.Run(context.Background(), &p)
	if res.Error == nil || !strings.HasPrefix(*res.Error, IntegrityPrefix) {
		t.Fatalf("expected integrity failure, got %+v", res)
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{"../evil name.msi": "evil_name.msi", "..": "file", "a/b\\c.exe": "c.exe"} {
		if got := safeName(in); got != want && !(runtime.GOOS != "windows" && in == "a/b\\c.exe" && got == "b_c.exe") {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitUTF8(t *testing.T) {
	b := []byte("Grüß") // ü = 2 bytes, ß = 2 bytes; cutting the last byte splits the ß
	valid, rest := splitUTF8(b[:len(b)-1])
	if string(valid) != "Grü" || len(rest) != 1 {
		t.Fatalf("got %q / %v", valid, rest)
	}
	valid, rest = splitUTF8(b)
	if string(valid) != "Grüß" || rest != nil {
		t.Fatalf("complete: %q / %v", valid, rest)
	}
}

func TestParamEnv(t *testing.T) {
	env := paramEnv(map[string]any{"name": "Max", "days": float64(7), "force": true, "ratio": 0.5})
	want := []string{"OPENCM_PARAM_DAYS=7", "OPENCM_PARAM_FORCE=true", "OPENCM_PARAM_NAME=Max", "OPENCM_PARAM_RATIO=0.5"}
	if strings.Join(env, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", env)
	}
}

type collector struct {
	mu     sync.Mutex
	chunks []Chunk
	cancel bool
}

func (c *collector) report(_ context.Context, ch []Chunk) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chunks = append(c.chunks, ch...)
	return c.cancel, nil
}

func (c *collector) text(stream string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, ch := range c.chunks {
		if ch.Stream == stream {
			b.WriteString(ch.Data)
		}
	}
	return b.String()
}

func script(unix, windows string) string {
	if runtime.GOOS == "windows" {
		return windows
	}
	return unix
}

func TestExecuteOutputExitCodeAndParams(t *testing.T) {
	c := &collector{}
	e := &Executor{WorkDir: t.TempDir(), Report: c.report, FlushInterval: 100 * time.Millisecond}
	content := script("echo \"hello $OPENCM_PARAM_NAME\"\necho oops >&2\nexit 3\n", "@echo off\r\necho hello %OPENCM_PARAM_NAME%\r\necho oops 1>&2\r\nexit /b 3\r\n")
	p := payload(content)
	p.Steps[0].Params = map[string]any{"name": "OpenCM"}
	p.Steps[0].CaptureOutput = true
	res := e.Run(context.Background(), &p)
	if res.Status != "failed" || res.ExitCode == nil || *res.ExitCode != 3 {
		t.Fatalf("result: %+v", res)
	}
	if !strings.Contains(c.text("stdout"), "hello OpenCM") || !strings.Contains(c.text("stderr"), "oops") {
		t.Fatalf("output: stdout=%q stderr=%q", c.text("stdout"), c.text("stderr"))
	}
	if !strings.Contains(res.Steps[0].StdoutTail, "hello OpenCM") {
		t.Fatalf("tail: %q", res.Steps[0].StdoutTail)
	}
}

func TestExecuteStopOnErrorAndContinue(t *testing.T) {
	e := &Executor{WorkDir: t.TempDir(), Report: (&collector{}).report}
	fail := script("exit 1", "@exit /b 1")
	ok := script("echo ok", "@echo ok")
	p := payload(fail)
	p.Steps = append(p.Steps, Step{Position: 1, Interpreter: shellInterpreter(), Content: ok, SHA256: hash(ok)})
	res := e.Run(context.Background(), &p)
	if res.Status != "failed" || res.Steps[1].Status != "skipped" {
		t.Fatalf("stopOnError: %+v", res)
	}
	p.Steps[0].ContinueOnError = true
	res = e.Run(context.Background(), &p)
	if res.Status != "succeeded" || res.Steps[0].Status != "failed" || res.Steps[1].Status != "succeeded" {
		t.Fatalf("continueOnError: %+v", res)
	}
}

func TestExecuteTimeout(t *testing.T) {
	e := &Executor{WorkDir: t.TempDir(), Report: (&collector{}).report}
	p := payload(script("sleep 30", "@ping -n 30 127.0.0.1 >nul"))
	p.TimeoutSeconds = 1
	start := time.Now()
	res := e.Run(context.Background(), &p)
	if res.Status != "timeout" {
		t.Fatalf("result: %+v", res)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("process tree not killed in time: %v", time.Since(start))
	}
}

func TestExecuteCancelFromServer(t *testing.T) {
	c := &collector{cancel: true}
	e := &Executor{WorkDir: t.TempDir(), Report: c.report, FlushInterval: 100 * time.Millisecond}
	p := payload(script("sleep 30", "@ping -n 30 127.0.0.1 >nul"))
	start := time.Now()
	res := e.Run(context.Background(), &p)
	if res.Status != "cancelled" || time.Since(start) > 15*time.Second {
		t.Fatalf("result: %+v after %v", res, time.Since(start))
	}
}

func TestMissingInterpreter(t *testing.T) {
	if _, _, err := commandFor("perl", "x"); err == nil {
		t.Fatal("expected error")
	}
}
