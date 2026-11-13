package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeartbeatAndErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/heartbeat":
			var req HeartbeatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentVersion != "1.0" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"serverTime":"2026-11-12T10:00:00Z","heartbeatSeconds":30,"inventoryRequested":true,"renewCertificate":false}`))
		case "/agent/v1/inventory":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"code":"device_not_authorized","message":"Unknown or revoked device certificate"}}`))
		}
	}))
	defer srv.Close()

	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	a := NewAgent(srv.URL, tlsCfg)
	res, err := a.Heartbeat(context.Background(), HeartbeatRequest{AgentVersion: "1.0"})
	if err != nil || !res.InventoryRequested || res.HeartbeatSeconds != 30 {
		t.Fatalf("heartbeat: %+v %v", res, err)
	}
	err = a.SubmitInventory(context.Background(), map[string]any{})
	if !IsRevoked(err) {
		t.Fatalf("expected revoked error, got %v", err)
	}
	if err.Error() != "HTTP 403: Unknown or revoked device certificate" {
		t.Fatalf("message: %q", err.Error())
	}
}

func TestEnrollRequiresHTTPS(t *testing.T) {
	if _, err := Enroll(context.Background(), "http://cm.example.org", nil, "", EnrollRequest{}); err == nil {
		t.Fatal("expected error for http URL")
	}
}

func TestEnrollServerPin(t *testing.T) {
	const ca, key = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n", "MCowBQYDK2VwAyEAkey"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(EnrollResponse{DeviceID: "d1", Certificate: "c", CACertificate: ca, AgentURL: "https://x:8443", SigningPublicKey: key})
	}))
	defer srv.Close()
	ctx := context.Background()

	// self-signed test server: without pin the certificate is rejected
	if _, err := Enroll(ctx, srv.URL, nil, "", EnrollRequest{}); err == nil {
		t.Fatal("untrusted certificate must be rejected without pin")
	}
	// with the right pin the certificate check is replaced by the pin check
	res, err := Enroll(ctx, srv.URL, nil, ServerPin(ca, key), EnrollRequest{})
	if err != nil || res.DeviceID != "d1" {
		t.Fatalf("pinned enrol: %+v %v", res, err)
	}
	// a different CA or signing key (man in the middle) is refused
	if _, err := Enroll(ctx, srv.URL, nil, ServerPin(ca, "other"), EnrollRequest{}); err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("expected pin mismatch, got %v", err)
	}
	if _, err := Enroll(ctx, srv.URL, nil, "md5:abc", EnrollRequest{}); err == nil {
		t.Fatal("invalid pin format must be rejected")
	}
	// fixed vector, shared with the server test (serverPin in enrollment.ts)
	if got := ServerPin("CA", "KEY"); got != "sha256:01dcf5d857839a9c80725000b9c2dfda46c7511ac4d9b2a05df9c544a91261f6" {
		t.Fatalf("pin vector: %s", got)
	}
}
