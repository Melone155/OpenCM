// Package config stores server profiles (URL + session token) in the user's
// config directory, e.g. ~/.config/opencm/config.json or %AppData%\opencm\config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Profile struct {
	Server   string `json:"server"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	// Insecure skips TLS verification (lab use only).
	Insecure bool `json:"insecure,omitempty"`
}

type Config struct {
	Current  string              `json:"current"`
	Profiles map[string]*Profile `json:"profiles"`
	path     string
}

// Path returns the config file location; OPENCM_CONFIG overrides it.
func Path() (string, error) {
	if p := os.Getenv("OPENCM_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "opencm", "config.json"), nil
}

func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	c := &Config{Profiles: map[string]*Profile{}, path: p}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	c.path = p
	return c, nil
}

// Save writes the config with 0600 permissions (it contains session tokens).
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Resolve returns the named profile, or the current one if name is empty.
func (c *Config) Resolve(name string) (string, *Profile, error) {
	if name == "" {
		name = c.Current
	}
	if name == "" {
		return "", nil, errors.New("no profile configured – run `opencm login --server <url>` first")
	}
	p, ok := c.Profiles[name]
	if !ok {
		return "", nil, fmt.Errorf("unknown profile %q", name)
	}
	return name, p, nil
}

func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
