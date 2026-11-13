package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(write(t, `{"serverUrl":"https://cm.example.org"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.HeartbeatInterval() != 60*time.Second {
		t.Errorf("heartbeat = %v", c.HeartbeatInterval())
	}
	if c.DataDir == "" {
		t.Error("DataDir not defaulted")
	}
	if c.SlogLevel() != slog.LevelInfo {
		t.Errorf("level = %v", c.SlogLevel())
	}
}

func TestLoadClampsHeartbeat(t *testing.T) {
	c, err := Load(write(t, `{"serverUrl":"https://cm.example.org","heartbeatSeconds":1,"logLevel":"debug"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.HeartbeatSeconds != 10 {
		t.Errorf("heartbeat = %d, want 10", c.HeartbeatSeconds)
	}
	if c.SlogLevel() != slog.LevelDebug {
		t.Errorf("level = %v", c.SlogLevel())
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"serverUrl":"http://cm.example.org"}`,
		`{"serverUrl":"not a url"}`,
		`{broken`,
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("expected error for %s", body)
		}
	}
}
