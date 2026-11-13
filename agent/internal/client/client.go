// Package client talks to the OpenCM server: enrolment over the public HTTPS
// API, everything else over the mTLS agent endpoint.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/opencm/opencm/agent/internal/tasks"
	"github.com/opencm/opencm/agent/internal/updater"
)

// StatusError is a non-2xx response.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &env) == nil && env.Error.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Code, env.Error.Message)
	}
	return fmt.Sprintf("HTTP %d", e.Code)
}

// IsRevoked reports whether the server rejected our certificate (403).
func IsRevoked(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusForbidden
}

func doJSON(ctx context.Context, c *http.Client, method, u string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "opencm-agent")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return &StatusError{Code: res.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// ---------------------------------------------------------------- enrolment

type EnrollRequest struct {
	Token        string `json:"token"`
	CSR          string `json:"csr"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"osVersion"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agentVersion"`
	MachineID    string `json:"machineId"`
}

type EnrollResponse struct {
	DeviceID             string    `json:"deviceId"`
	Certificate          string    `json:"certificate"`
	CACertificate        string    `json:"caCertificate"`
	CertificateExpiresAt time.Time `json:"certificateExpiresAt"`
	AgentURL             string    `json:"agentUrl"`
	HeartbeatSeconds     int       `json:"heartbeatSeconds"`
	SigningPublicKey     string    `json:"signingPublicKey"`
}

// ServerPin is the fingerprint of what an agent must trust after enrolment: the CA of the
// mTLS endpoint and the task signing key. Format "sha256:<hex>" over
// caCertificate + "\n" + signingPublicKey, exactly as returned by the enroll endpoint.
// Must stay in sync with serverPin() in server/src/routes/enrollment.ts.
func ServerPin(caCertificate, signingPublicKey string) string {
	sum := sha256.Sum256([]byte(caCertificate + "\n" + signingPublicKey))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Enroll exchanges the token + CSR for a certificate. serverURL must be HTTPS;
// extraCA (optional PEM) is trusted in addition to the system roots, for servers
// with an internal CA.
//
// With pin (see ServerPin) the HTTPS certificate of serverURL is not verified – e.g. a
// reverse proxy with a self-signed/local CA. Instead the response must match the pin, which
// the generated install script got from the server over a checksum-verified channel. A
// man in the middle could then read the token, but not make the agent trust him: all later
// traffic uses mTLS against the pinned CA, and tasks must carry the pinned signature.
func Enroll(ctx context.Context, serverURL string, extraCA []byte, pin string, req EnrollRequest) (*EnrollResponse, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("server URL must be https://…, got %q", serverURL)
	}
	if pin != "" && !strings.HasPrefix(pin, "sha256:") {
		return nil, fmt.Errorf("--server-pin must look like sha256:<hex>, got %q", pin)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if len(extraCA) > 0 && !pool.AppendCertsFromPEM(extraCA) {
		return nil, errors.New("--ca-file contains no valid certificate")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if pin != "" {
		tr.TLSClientConfig.InsecureSkipVerify = true // replaced by the pin check below
	}
	c := &http.Client{Timeout: 60 * time.Second, Transport: tr}
	res := &EnrollResponse{}
	if err := doJSON(ctx, c, http.MethodPost, strings.TrimRight(serverURL, "/")+"/api/v1/agent/enroll", req, res); err != nil {
		return nil, err
	}
	if res.DeviceID == "" || res.Certificate == "" || res.AgentURL == "" {
		return nil, errors.New("incomplete enrolment response")
	}
	if pin != "" {
		got := ServerPin(res.CACertificate, res.SigningPublicKey)
		if res.SigningPublicKey == "" || subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(pin))) != 1 {
			return nil, errors.New("server pin mismatch – the response did not come from the expected OpenCM server")
		}
	}
	return res, nil
}

// ---------------------------------------------------------------- mTLS agent endpoint

type Agent struct {
	base string
	http *http.Client
	// large installer downloads (bandwidth limited by the server) – bounded by the task context, not a fixed timeout
	dl *http.Client
}

func NewAgent(agentURL string, tlsCfg *tls.Config) *Agent {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.MaxIdleConns = 2
	return &Agent{base: strings.TrimRight(agentURL, "/") + "/agent/v1", http: &http.Client{Timeout: 5 * time.Minute, Transport: tr}, dl: &http.Client{Transport: tr}}
}

// Close releases idle connections (call before replacing the client after renewal).
func (a *Agent) Close() { a.http.CloseIdleConnections() }

// DownloadFile streams an installer file (by SHA-256) of the current task into w.
// The caller verifies the hash of what was written.
func (a *Agent) DownloadFile(ctx context.Context, sha256 string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/files/"+url.PathEscape(sha256), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "opencm-agent")
	res, err := a.dl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		return &StatusError{Code: res.StatusCode, Body: string(b)}
	}
	_, err = io.Copy(w, res.Body)
	return err
}

type HeartbeatRequest struct {
	AgentVersion  string   `json:"agentVersion"`
	Hostname      string   `json:"hostname,omitempty"`
	LoggedOnUsers []string `json:"loggedOnUsers,omitempty"`
	UptimeSeconds float64  `json:"uptimeSeconds,omitempty"`
	AgentStarted  bool     `json:"agentStarted,omitempty"`
}

type HeartbeatResponse struct {
	ServerTime         time.Time       `json:"serverTime"`
	HeartbeatSeconds   int             `json:"heartbeatSeconds"`
	InventoryRequested bool            `json:"inventoryRequested"`
	RenewCertificate   bool            `json:"renewCertificate"`
	Update             *updater.Offer  `json:"update"`
}

func (a *Agent) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResponse, error) {
	res := &HeartbeatResponse{}
	return res, doJSON(ctx, a.http, http.MethodPost, a.base+"/heartbeat", req, res)
}

func (a *Agent) SubmitInventory(ctx context.Context, inv any) error {
	return doJSON(ctx, a.http, http.MethodPost, a.base+"/inventory", inv, nil)
}

type RenewResponse struct {
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"caCertificate"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func (a *Agent) Renew(ctx context.Context, csrPEM string) (*RenewResponse, error) {
	res := &RenewResponse{}
	return res, doJSON(ctx, a.http, http.MethodPost, a.base+"/certificate/renew", map[string]string{"csr": csrPEM}, res)
}

// SigningKey fetches the server's task-signing key (for agents enrolled before M2).
func (a *Agent) SigningKey(ctx context.Context) (string, error) {
	var res struct {
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"publicKey"`
	}
	if err := doJSON(ctx, a.http, http.MethodGet, a.base+"/signing-key", nil, &res); err != nil {
		return "", err
	}
	if res.Algorithm != "ed25519" {
		return "", fmt.Errorf("unsupported signing algorithm %q", res.Algorithm)
	}
	return res.PublicKey, nil
}

// NextTask long-polls for a task; returns nil, nil when none arrived within wait.
func (a *Agent) NextTask(ctx context.Context, wait time.Duration) (*tasks.Envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/tasks/next?wait=%d", a.base, int(wait.Seconds())), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "opencm-agent")
	res, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		env := &tasks.Envelope{}
		return env, json.Unmarshal(data, env)
	}
	return nil, &StatusError{Code: res.StatusCode, Body: string(data)}
}

type cancelFlag struct {
	Cancel bool `json:"cancel"`
}

func (a *Agent) StartTask(ctx context.Context, taskID string) (bool, error) {
	var res cancelFlag
	err := doJSON(ctx, a.http, http.MethodPost, a.base+"/tasks/"+url.PathEscape(taskID)+"/start", map[string]any{}, &res)
	return res.Cancel, err
}

func (a *Agent) TaskOutput(ctx context.Context, taskID string, chunks []tasks.Chunk) (bool, error) {
	var res cancelFlag
	err := doJSON(ctx, a.http, http.MethodPost, a.base+"/tasks/"+url.PathEscape(taskID)+"/output", map[string]any{"chunks": chunks}, &res)
	return res.Cancel, err
}

func (a *Agent) TaskResult(ctx context.Context, taskID string, result tasks.Result) error {
	return doJSON(ctx, a.http, http.MethodPost, a.base+"/tasks/"+url.PathEscape(taskID)+"/result", result, nil)
}

// DownloadUpdate streams the agent binary for this platform into w.
func (a *Agent) DownloadUpdate(ctx context.Context, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/update/download", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "opencm-agent")
	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		return &StatusError{Code: res.StatusCode, Body: string(b)}
	}
	_, err = io.Copy(w, io.LimitReader(res.Body, 512<<20))
	return err
}
