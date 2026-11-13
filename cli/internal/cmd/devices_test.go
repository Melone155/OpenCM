package cmd

import (
	"net/url"
	"testing"
)

func TestParseFilter(t *testing.T) {
	q := url.Values{}
	if err := parseFilter("os=windows, online=true ,hostname=PC-01", q); err != nil {
		t.Fatal(err)
	}
	if q.Get("os") != "windows" || q.Get("online") != "true" || q.Get("search") != "PC-01" {
		t.Fatalf("unexpected: %v", q)
	}
	q = url.Values{}
	_ = parseFilter("os=mac", q)
	if q.Get("os") != "macos" {
		t.Fatalf("alias: %v", q)
	}
	for _, bad := range []string{"os", "color=red", "os="} {
		if err := parseFilter(bad, url.Values{}); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	if err := parseFilter("  ", url.Values{}); err != nil {
		t.Errorf("empty filter: %v", err)
	}
}

func TestTokenState(t *testing.T) {
	two := 2
	rev := "2026-01-01T00:00:00Z"
	future, past := "2999-01-01T00:00:00Z", "2000-01-01T00:00:00Z"
	cases := map[string]enrollmentToken{
		"active":  {ExpiresAt: &future},
		"expired": {ExpiresAt: &past},
		"used up": {ExpiresAt: &future, MaxUses: &two, Uses: 2},
		"revoked": {ExpiresAt: &future, RevokedAt: &rev},
	}
	for want, tok := range cases {
		if got := tokenState(tok); got != want {
			t.Errorf("tokenState = %q, want %q", got, want)
		}
	}
	// no expiry date = never expires
	if got := tokenState(enrollmentToken{}); got != "active" || tokenExpiry(enrollmentToken{}) != "never" {
		t.Errorf("unlimited token: state %q, expiry %q", got, tokenExpiry(enrollmentToken{}))
	}
}
