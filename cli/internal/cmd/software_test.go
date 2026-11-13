package cmd

import (
	"reflect"
	"testing"
)

func TestParseSoftwareRule(t *testing.T) {
	cases := map[string]map[string]any{
		"7-Zip*>=24.08": {"type": "software", "name": "7-Zip*", "version": "24.08", "operator": "gte"},
		"htop":          {"type": "software", "name": "htop"},
		"App = 1.0":     {"type": "software", "name": "App", "version": "1.0", "operator": "eq"},
		"Old<2":         {"type": "software", "name": "Old", "version": "2", "operator": "lt"},
	}
	for in, want := range cases {
		got, err := parseSoftwareRule(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseSoftwareRule(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "App>=", "   "} {
		if _, err := parseSoftwareRule(bad); err == nil {
			t.Errorf("parseSoftwareRule(%q): expected error", bad)
		}
	}
}

func TestFindVersion(t *testing.T) {
	p := &pkg{Name: "X", Versions: []pkgVersion{{Version: "3", Status: "draft"}, {Version: "2", Status: "approved"}, {Version: "1", Status: "retired"}}}
	if v, err := findVersion(p, ""); err != nil || v.Version != "2" {
		t.Fatalf("newest approved: %v %v", v, err)
	}
	if v, err := findVersion(p, "3"); err != nil || v.Version != "3" {
		t.Fatalf("explicit: %v %v", v, err)
	}
	if _, err := findVersion(p, "9"); err == nil {
		t.Fatal("unknown version must fail")
	}
}
