package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Chunk of process output.
type Chunk struct {
	Stream string `json:"stream"` // stdout | stderr
	Data   string `json:"data"`
}

// Reporter sends output to the server and reports whether the task was cancelled.
type Reporter func(ctx context.Context, chunks []Chunk) (cancel bool, err error)

type StepResult struct {
	Position   int    `json:"position"`
	Status     string `json:"status"` // succeeded | failed | skipped | timeout | cancelled
	ExitCode   *int   `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	StdoutTail string `json:"stdoutTail,omitempty"`
	// Integrity is set when the step was refused because of a hash mismatch (not sent per step;
	// it becomes the task's error so the server can flag it).
	Integrity string `json:"-"`
}

// Downloader streams the file with the given SHA-256 from the server into w.
type Downloader func(ctx context.Context, sha256 string, w io.Writer) error

type Result struct {
	Status   string       `json:"status"` // succeeded | failed | timeout | cancelled
	ExitCode *int         `json:"exitCode"`
	Error    *string      `json:"error"`
	Steps    []StepResult `json:"steps"`
}

const (
	flushInterval = time.Second
	flushBytes    = 32 * 1024
	tailBytes     = 8 * 1024
)

// Executor runs verified payloads.
type Executor struct {
	WorkDir string
	Report  Reporter
	// Download fetches installer files of package steps (nil: steps with files fail).
	Download Downloader
	// FlushInterval overrides the output flush interval (tests).
	FlushInterval time.Duration
}

// outputBuffer collects stdout/stderr, keeps UTF-8 sequences intact across
// reads and remembers the stdout tail.
type outputBuffer struct {
	mu      sync.Mutex
	chunks  []Chunk
	pending map[string][]byte // incomplete UTF-8 suffix per stream
	size    int
	tail    []byte
}

func newOutputBuffer() *outputBuffer { return &outputBuffer{pending: map[string][]byte{}} }

// splitUTF8 returns the longest prefix that does not end in an incomplete rune.
func splitUTF8(b []byte) (valid, rest []byte) {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i], b[i:]
			}
			break
		}
	}
	return b, nil
}

func (o *outputBuffer) write(stream string, p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	data := append(o.pending[stream], p...)
	valid, rest := splitUTF8(data)
	o.pending[stream] = append([]byte(nil), rest...)
	if len(valid) == 0 {
		return
	}
	if stream == "stdout" {
		o.tail = append(o.tail, valid...)
		if len(o.tail) > tailBytes {
			o.tail = o.tail[len(o.tail)-tailBytes:]
		}
	}
	if n := len(o.chunks); n > 0 && o.chunks[n-1].Stream == stream {
		o.chunks[n-1].Data += string(valid)
	} else {
		o.chunks = append(o.chunks, Chunk{Stream: stream, Data: string(valid)})
	}
	o.size += len(valid)
}

func (o *outputBuffer) take(final bool) []Chunk {
	o.mu.Lock()
	defer o.mu.Unlock()
	if final {
		for _, s := range []string{"stdout", "stderr"} {
			if len(o.pending[s]) > 0 {
				o.chunks = append(o.chunks, Chunk{Stream: s, Data: string(o.pending[s])})
				o.pending[s] = nil
			}
		}
	}
	c := o.chunks
	o.chunks, o.size = nil, 0
	return c
}

func (o *outputBuffer) bytes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.size
}

type streamWriter struct {
	buf    *outputBuffer
	stream string
}

func (w streamWriter) Write(p []byte) (int, error) {
	w.buf.write(w.stream, p)
	return len(p), nil
}

func intp(i int) *int { return &i }

// Run executes all steps of a verified payload sequentially.
func (e *Executor) Run(ctx context.Context, p *Payload) Result {
	ctx, cancelTimeout := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancelTimeout()
	cancelCtx, cancelTask := context.WithCancel(ctx)
	defer cancelTask()

	res := Result{Status: "succeeded"}
	stop := false
	var cancelled bool
	for _, step := range p.Steps {
		if stop {
			res.Steps = append(res.Steps, StepResult{Position: step.Position, Status: "skipped"})
			continue
		}
		sr := e.runStep(cancelCtx, cancelTask, p, step)
		res.Steps = append(res.Steps, sr)
		res.ExitCode = sr.ExitCode
		if sr.Integrity != "" {
			// tampering detected: abort the whole task, never continue with further steps
			msg := sr.Integrity
			res.Error = &msg
			res.Status = "failed"
			stop = true
			continue
		}
		switch sr.Status {
		case "cancelled":
			cancelled = true
			stop = true
		case "timeout":
			res.Status = "timeout"
			stop = true
		case "failed":
			if !step.ContinueOnError {
				if res.Status == "succeeded" {
					res.Status = "failed"
				}
				if p.StopOnError {
					stop = true
				}
			}
		}
	}
	if cancelled {
		res.Status = "cancelled"
	}
	return res
}

// runStep executes one step. ctx is cancelled on user cancel / agent shutdown
// (context.Canceled) or when the task timeout expires (context.DeadlineExceeded).
func (e *Executor) runStep(ctx context.Context, cancelTask context.CancelFunc, p *Payload, step Step) StepResult {
	start := time.Now()
	sr := StepResult{Position: step.Position}
	out := newOutputBuffer()
	fail := func(msg string) StepResult {
		out.write("stderr", []byte("[opencm-agent] "+msg+"\n"))
		e.flush(context.WithoutCancel(ctx), out, true)
		sr.Status, sr.DurationMs = "failed", time.Since(start).Milliseconds()
		return sr
	}

	integrity := func(msg string) StepResult {
		r := fail("ABGEBROCHEN – Hash-Prüfung fehlgeschlagen: " + msg)
		r.Integrity = IntegrityPrefix + msg
		return r
	}

	// the content was verified in Verify; check again right before execution
	if sha256Hex([]byte(step.Content)) != step.SHA256 {
		return integrity(fmt.Sprintf("step %d: content hash mismatch", step.Position))
	}

	// installer files: download, verify SHA-256 1:1, pass paths as OPENCM_FILE_<n>
	var fileEnv []string
	if len(step.Files) > 0 {
		dir := filepath.Join(e.WorkDir, fmt.Sprintf("task-%s-%d-files", p.TaskID, step.Position))
		defer os.RemoveAll(dir)
		paths, msg, err := e.fetchFiles(ctx, dir, step.Files)
		if msg != "" {
			return integrity(msg)
		}
		if err != nil {
			return fail("file download failed: " + err.Error())
		}
		for i, path := range paths {
			fileEnv = append(fileEnv, fmt.Sprintf("OPENCM_FILE_%d=%s", i+1, path))
		}
		fileEnv = append(fileEnv, "OPENCM_FILES_DIR="+dir)
	}

	ext, data := scriptFile(step.Interpreter, step.Content)
	file := filepath.Join(e.WorkDir, fmt.Sprintf("task-%s-%d%s", p.TaskID, step.Position, ext))
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return fail("cannot write script file: " + err.Error())
	}
	defer os.Remove(file)
	// the file on disk must be exactly what was verified
	if onDisk, err := os.ReadFile(file); err != nil || sha256Hex(onDisk) != sha256Hex(data) {
		return integrity(fmt.Sprintf("step %d: script file on disk was modified before execution", step.Position))
	}

	bin, args, err := commandFor(step.Interpreter, file)
	if err != nil {
		return fail(err.Error())
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = e.WorkDir
	cmd.Env = append(os.Environ(), paramEnv(step.Params)...)
	cmd.Env = append(cmd.Env, fileEnv...)
	cmd.Env = append(cmd.Env, "OPENCM_TASK_ID="+p.TaskID, "OPENCM_DEVICE_ID="+p.DeviceID, fmt.Sprintf("OPENCM_STEP=%d", step.Position))
	cmd.Stdin = nil
	cmd.Stdout = streamWriter{out, "stdout"}
	cmd.Stderr = streamWriter{out, "stderr"}
	setupProcess(cmd)
	cmd.Cancel = func() error { return killTree(cmd) }
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		return fail("cannot start interpreter: " + err.Error())
	}

	// flush loop: send output regularly, react to cancellation
	done := make(chan struct{})
	userCancelled := false
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		interval := e.FlushInterval
		if interval <= 0 {
			interval = flushInterval
		}
		t := time.NewTicker(interval / 4)
		defer t.Stop()
		last := time.Now()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(last) < interval && out.bytes() < flushBytes {
					continue
				}
				last = time.Now()
				if e.flush(ctx, out, false) {
					userCancelled = true
					cancelTask()
				}
			}
		}
	}()

	waitErr := cmd.Wait()
	close(done)
	wg.Wait()
	if e.flush(context.WithoutCancel(ctx), out, true) {
		userCancelled = true
	}

	sr.DurationMs = time.Since(start).Milliseconds()
	if step.CaptureOutput {
		out.mu.Lock()
		sr.StdoutTail = string(out.tail)
		out.mu.Unlock()
	}
	var exitErr *exec.ExitError
	switch {
	case userCancelled || errors.Is(ctx.Err(), context.Canceled):
		sr.Status = "cancelled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		sr.Status = "timeout"
	case waitErr == nil:
		sr.Status, sr.ExitCode = "succeeded", intp(0)
	case errors.As(waitErr, &exitErr):
		sr.Status, sr.ExitCode = "failed", intp(exitErr.ExitCode())
	default:
		sr.Status = "failed"
		out.write("stderr", []byte("[opencm-agent] "+waitErr.Error()+"\n"))
		e.flush(context.WithoutCancel(ctx), out, true)
	}
	return sr
}

// flush sends buffered output; returns true if the server requested cancellation.
func (e *Executor) flush(ctx context.Context, out *outputBuffer, final bool) bool {
	chunks := out.take(final)
	if len(chunks) == 0 && !final {
		// heartbeat to learn about cancellation even without output
		chunks = []Chunk{}
	}
	if e.Report == nil {
		return false
	}
	cancel, err := e.Report(ctx, chunks)
	return err == nil && cancel
}

var _ io.Writer = streamWriter{}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// safeName keeps letters, digits, dot, dash and underscore of a file name (no paths).
func safeName(name string) string {
	var b strings.Builder
	for _, r := range filepath.Base(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), ".")
	if s == "" {
		s = "file"
	}
	return s
}

// fetchFiles downloads every file and verifies its SHA-256 against the signed payload.
// A non-empty integrity message means the content did not match – it must not be used.
func (e *Executor) fetchFiles(ctx context.Context, dir string, files []File) (paths []string, integrity string, err error) {
	if e.Download == nil {
		return nil, "", errors.New("this agent has no file download configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	for i, f := range files {
		path := filepath.Join(dir, fmt.Sprintf("%d-%s", i+1, safeName(f.Name)))
		var lastErr error
		for attempt := 0; attempt < 3; attempt++ {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			got, err := e.downloadOnce(ctx, f.SHA256, path)
			if err != nil {
				lastErr = err
				continue
			}
			if got != f.SHA256 {
				os.Remove(path)
				return nil, fmt.Sprintf("file %q: SHA-256 %s does not match expected %s", f.Name, got, f.SHA256), nil
			}
			lastErr = nil
			break
		}
		if lastErr != nil {
			return nil, "", fmt.Errorf("%s: %w", f.Name, lastErr)
		}
		paths = append(paths, path)
	}
	return paths, "", nil
}

func (e *Executor) downloadOnce(ctx context.Context, sha string, path string) (string, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	err = e.Download(ctx, sha, io.MultiWriter(out, h))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
