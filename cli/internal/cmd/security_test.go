package cmd

import (
	"encoding/json"
	"testing"
)

func TestRunDecodes(t *testing.T) {
	var r run
	if err := json.Unmarshal([]byte(`{"id":"r1","name":"Job","status":"running","counts":{"pending":2}}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "r1" || r.Counts["pending"] != 2 {
		t.Fatalf("unexpected run decode: %+v", r)
	}
}
