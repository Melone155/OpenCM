// Package identity manages the agent's key pair, certificates and enrolment state
// in the data directory. The private key is generated locally and never leaves
// the device.
package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	keyFile        = "agent.key"
	certFile       = "agent.crt"
	caFile         = "ca.crt"
	stateFile      = "state.json"
	signingKeyFile = "signing.pub"
	workDir        = "work"
)

// SaveSigningKey stores the server's Ed25519 public key (raw 32 bytes, base64).
func (s Store) SaveSigningKey(b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("invalid signing key")
	}
	return writeAtomic(s.path(signingKeyFile), []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o644)
}

// SigningKey loads the stored key; os.ErrNotExist if none is stored yet.
func (s Store) SigningKey() (ed25519.PublicKey, error) {
	b, err := os.ReadFile(s.path(signingKeyFile))
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("stored signing key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

// WorkDir is where task scripts are written (inside the protected data dir).
func (s Store) WorkDir() (string, error) {
	d := s.path(workDir)
	return d, os.MkdirAll(d, 0o700)
}

// ErrNotEnrolled is returned when no enrolment state exists yet.
var ErrNotEnrolled = errors.New("agent is not enrolled – run `opencm-agent enroll --server <url> --token <token>`")

type State struct {
	DeviceID         string    `json:"deviceId"`
	ServerURL        string    `json:"serverUrl"`
	AgentURL         string    `json:"agentUrl"`
	HeartbeatSeconds int       `json:"heartbeatSeconds"`
	CertExpiresAt    time.Time `json:"certExpiresAt"`
	LastInventoryAt  time.Time `json:"lastInventoryAt"`
}

type Store struct{ Dir string }

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Init creates the data directory and restricts access to SYSTEM/Administrators (Windows) or root (Unix).
func (s Store) Init() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return secureDir(s.Dir)
}

// PrepareConfigDir creates or hardens the directory that holds the agent configuration
// (and, by default, the data directory). trustedBefore is false when the directory already
// existed and belonged to someone else: its previous content (an agent.json planted before
// the installation) must then be ignored by the caller.
func PrepareConfigDir(dir string) (trustedBefore bool, err error) {
	if _, statErr := os.Stat(dir); errors.Is(statErr, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, err
		}
		trustedBefore = true
	} else if statErr != nil {
		return false, statErr
	} else if trustedBefore, err = OwnerTrusted(dir); err != nil {
		return false, err
	}
	return trustedBefore, hardenConfigDir(dir, trustedBefore)
}

// AssertTrusted refuses to work with configuration or key material that an unprivileged
// user could have planted or can replace. Paths that do not exist are skipped.
func AssertTrusted(paths ...string) error {
	for _, p := range paths {
		ok, err := OwnerTrusted(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("check owner of %s: %w", p, err)
		}
		if !ok {
			return fmt.Errorf("%s is not owned by the system/administrators (or is writable by others) – refusing to use it; run `opencm-agent enroll` again as administrator", p)
		}
	}
	return nil
}

// NewKeyAndCSR generates an ECDSA P-256 key and a CSR. The server ignores the
// requested subject and assigns CN=<deviceId>.
func NewKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SaveCredentials validates that cert and key belong together and stores them with the CA.
func (s Store) SaveCredentials(keyPEM, certPEM, caPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate does not match key: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid CA certificate")
	}
	if err := writeAtomic(s.path(keyFile), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(s.path(certFile), certPEM, 0o644); err != nil {
		return err
	}
	return writeAtomic(s.path(caFile), caPEM, 0o644)
}

// TLSConfig returns the mTLS client configuration: our certificate, and only the
// OpenCM CA as trust anchor for the agent endpoint.
func (s Store) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.path(certFile), s.path(keyFile))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(s.path(caFile))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate in data dir")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// CertNotAfter reads the expiry of the stored client certificate.
func (s Store) CertNotAfter() (time.Time, error) {
	b, err := os.ReadFile(s.path(certFile))
	if err != nil {
		return time.Time{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, errors.New("invalid certificate PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

func (s Store) LoadState() (*State, error) {
	b, err := os.ReadFile(s.path(stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if st.DeviceID == "" || st.AgentURL == "" {
		return nil, ErrNotEnrolled
	}
	return st, nil
}

func (s Store) SaveState(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path(stateFile), b, 0o600)
}
