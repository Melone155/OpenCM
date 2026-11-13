package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opencm/opencm/cli/internal/api"
)

func TestParseParams(t *testing.T) {
	defs := []scriptParam{{Name: "Days", Type: "number"}, {Name: "Force", Type: "boolean"}, {Name: "Mode", Type: "string"}}
	got, err := parseParams(defs, []string{"days=7", "Force=true", "Mode=a=b"})
	if err != nil {
		t.Fatal(err)
	}
	if got["Days"] != 7.0 || got["Force"] != true || got["Mode"] != "a=b" {
		t.Fatalf("got %#v", got)
	}
	for _, bad := range [][]string{{"Days=x"}, {"Force=maybe"}, {"Unknown=1"}, {"noequals"}} {
		if _, err := parseParams(defs, bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestParseTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/device-groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "g-1", "name": "Buchhaltung"}}})
		case "/api/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "d-1", "hostname": "PC-0815"}, {"id": "d-2", "hostname": "PC-08150"}}})
		}
	}))
	defer srv.Close()
	c := api.New(srv.URL, "t", false)

	tg, err := parseTargets(c, []string{"group:buchhaltung", "device:pc-0815", "6f9619ff-8b86-d011-b42d-00cf4fc964ff"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.GroupIDs) != 1 || tg.GroupIDs[0] != "g-1" || len(tg.DeviceIDs) != 2 || tg.DeviceIDs[0] != "d-1" {
		t.Fatalf("got %+v", tg)
	}
	all, _ := parseTargets(c, []string{"all"})
	if !all.AllDevices {
		t.Fatal("all")
	}
	for _, bad := range [][]string{{"group:Unbekannt"}, {"device:nope"}, {"planet:mars"}, {}} {
		if _, err := parseTargets(c, bad); err == nil {
			t.Errorf("expected error for %v", bad)
		}
	}
}

func TestCountsText(t *testing.T) {
	if got := countsText(map[string]int{"total": 3, "succeeded": 2, "failed": 1, "pending": 0}); got != "3 devices: failed=1 succeeded=2" {
		t.Fatalf("got %q", got)
	}
}
