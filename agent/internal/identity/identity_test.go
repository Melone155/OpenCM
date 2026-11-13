package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// signWithTestCA plays the server: issues a client cert for the CSR.
func signWithTestCA(t *testing.T, csrPEM []byte) (certPEM, caPEM []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("bad csr: %v", err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device-1"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(365 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func TestEnrolmentRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.LoadState(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}
	keyPEM, csrPEM, err := NewKeyAndCSR("pc-0001")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := signWithTestCA(t, csrPEM)

	// mismatching key must be rejected
	otherKey, _, _ := NewKeyAndCSR("x")
	if err := s.SaveCredentials(otherKey, certPEM, caPEM); err == nil {
		t.Fatal("expected key/cert mismatch error")
	}
	if err := s.SaveCredentials(keyPEM, certPEM, caPEM); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.TLSConfig()
	if err != nil || len(cfg.Certificates) != 1 || cfg.RootCAs == nil || cfg.MinVersion < 0x0303 {
		t.Fatalf("tls config: %v %+v", err, cfg)
	}
	na, err := s.CertNotAfter()
	if err != nil || time.Until(na) < 364*24*time.Hour {
		t.Fatalf("notAfter %v %v", na, err)
	}

	st := &State{DeviceID: "device-1", AgentURL: "https://cm.example.org:8443", HeartbeatSeconds: 60}
	if err := s.SaveState(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadState()
	if err != nil || got.DeviceID != "device-1" || got.HeartbeatSeconds != 60 {
		t.Fatalf("state: %+v %v", got, err)
	}
}
