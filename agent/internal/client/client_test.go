package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if _, err := Enroll(context.Background(), "http://cm.example.org", nil, EnrollRequest{}); err == nil {
		t.Fatal("expected error for http URL")
	}
}
