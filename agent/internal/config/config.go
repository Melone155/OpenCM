// Package config loads the agent configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Config struct {
	// ServerURL of the OpenCM server, e.g. https://cm.example.org
	ServerURL string `json:"serverUrl"`
	// DataDir holds the client certificate, key and CA bundle after enrollment.
	DataDir string `json:"dataDir"`
	// HeartbeatSeconds between check-ins (default 60, min 10).
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	LogLevel         string `json:"logLevel"`
}

// DefaultPath is the platform-specific config location.
func DefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "OpenCM", "agent.json")
	case "darwin":
		return "/Library/Application Support/OpenCM/agent.json"
	default:
		return "/etc/opencm/agent.json"
	}
}

func defaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(filepath.Dir(DefaultPath()), "data")
	case "darwin":
		return "/Library/Application Support/OpenCM/data"
	default:
		return "/var/lib/opencm"
	}
}

// New returns a normalized config for serverURL (used by `enroll`).
func New(serverURL string) (*Config, error) {
	c := &Config{ServerURL: serverURL}
	return c, c.normalize()
}

// Save writes the config file (directory is created if needed).
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, c.normalize()
}

func (c *Config) normalize() error {
	if c.ServerURL == "" {
		return errors.New("serverUrl is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid serverUrl %q", c.ServerURL)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("serverUrl must use https (got %q)", u.Scheme)
	}
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 60
	}
	if c.HeartbeatSeconds < 10 {
		c.HeartbeatSeconds = 10
	}
	return nil
}

func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatSeconds) * time.Second
}

func (c *Config) SlogLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return slog.LevelInfo
	}
	return l
}
