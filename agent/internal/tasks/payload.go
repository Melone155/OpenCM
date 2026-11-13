// Package tasks verifies and executes signed tasks from the server.
package tasks

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// Envelope as delivered by GET /agent/v1/tasks/next.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// File is an installer file the agent downloads (mTLS) before the step runs.
type File struct {
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
}

// IntegrityPrefix marks every refusal caused by a hash or signature mismatch, so the
// server can show it as "aborted because of a wrong hash".
const IntegrityPrefix = "integrity: "

type Step struct {
	Position        int            `json:"position"`
	Name            string         `json:"name"`
	Version         int            `json:"version"`
	Interpreter     string         `json:"interpreter"`
	Content         string         `json:"content"`
	SHA256          string         `json:"sha256"`
	Params          map[string]any `json:"params"`
	ContinueOnError bool           `json:"continueOnError"`
	CaptureOutput   bool           `json:"captureOutput"`
	Files           []File         `json:"files,omitempty"`
}

type Payload struct {
	V              int       `json:"v"`
	TaskID         string    `json:"taskId"`
	RunID          string    `json:"runId"`
	DeviceID       string    `json:"deviceId"`
	Attempt        int       `json:"attempt"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	StopOnError    bool      `json:"stopOnError"`
	Steps          []Step    `json:"steps"`
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ClockSkew tolerated when checking expiresAt.
const ClockSkew = 5 * time.Minute

// ErrVerification wraps every reason to refuse a task.
var ErrVerification = errors.New("task verification failed")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerification, fmt.Sprintf(format, a...))
}

// PeekTaskID reads the task id from an (unverified!) envelope, only to report a
// refusal back to the server. Never use other unverified fields.
func PeekTaskID(env *Envelope) string {
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}
	var p struct {
		TaskID string `json:"taskId"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.TaskID) > 64 {
		return ""
	}
	return p.TaskID
}

// Verify checks the server signature over the exact payload bytes and then the
// task's binding to this device, its expiry and every step's content hash and
// interpreter. Nothing is executed unless Verify succeeds.
func Verify(env *Envelope, pub ed25519.PublicKey, deviceID string, now time.Time) (*Payload, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, refuse("no valid signing key configured")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, refuse("payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, refuse("malformed signature")
	}
	if !ed25519.Verify(pub, raw, sig) {
		return nil, refuse(IntegrityPrefix + "signature does not match")
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, refuse("payload is not valid JSON")
	}
	if p.V != 1 && p.V != 2 {
		return nil, refuse("unsupported payload version %d", p.V)
	}
	if p.DeviceID != deviceID {
		return nil, refuse("task is addressed to another device")
	}
	if now.After(p.ExpiresAt.Add(ClockSkew)) {
		return nil, refuse("task expired at %s", p.ExpiresAt.Format(time.RFC3339))
	}
	if len(p.Steps) == 0 {
		return nil, refuse("task has no steps")
	}
	for _, s := range p.Steps {
		sum := sha256.Sum256([]byte(s.Content))
		if hex.EncodeToString(sum[:]) != s.SHA256 {
			return nil, refuse(IntegrityPrefix+"step %d: content hash mismatch", s.Position)
		}
		if len(s.Files) > 0 && p.V < 2 {
			return nil, refuse("step %d: files require payload version 2", s.Position)
		}
		for _, f := range s.Files {
			if !validSHA256(f.SHA256) {
				return nil, refuse("step %d: invalid file hash", s.Position)
			}
		}
		if !Supported(s.Interpreter, runtime.GOOS) {
			return nil, refuse("step %d: interpreter %q is not supported on %s", s.Position, s.Interpreter, runtime.GOOS)
		}
	}
	if p.TimeoutSeconds <= 0 {
		p.TimeoutSeconds = 3600
	}
	return &p, nil
}
