package cmd

import "testing"

func TestVulnFormatting(t *testing.T) {
	s := 9.8
	e := 0.0042
	if score(&s) != "9.8" || score(nil) != "-" {
		t.Fatal("score")
	}
	if percent(&e) != "0.4%" || percent(nil) != "-" {
		t.Fatalf("percent: %s", percent(&e))
	}
	if kevMark(vuln{Kev: true}) != "KEV" || kevMark(vuln{}) != "" {
		t.Fatal("kev")
	}
}
