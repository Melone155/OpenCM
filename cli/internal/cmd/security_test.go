package cmd

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestRunStartDecodesRunAndApproval(t *testing.T) {
	var r runStart
	if err := json.Unmarshal([]byte(`{"id":"r1","name":"Job","status":"running","counts":{"pending":2}}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.ApprovalRequired || r.ID != "r1" || r.Counts["pending"] != 2 {
		t.Fatalf("unexpected run decode: %+v", r)
	}

	var p runStart
	if err := json.Unmarshal([]byte(`{"approvalRequired":true,"approvalId":"a1","devices":120}`), &p); err != nil {
		t.Fatal(err)
	}
	if !p.ApprovalRequired || p.ApprovalID != "a1" || p.Devices != 120 {
		t.Fatalf("unexpected approval decode: %+v", p)
	}
}

func TestPendingApprovalExitCode(t *testing.T) {
	var err error = &pendingApprovalError{"a1"}
	var pending *pendingApprovalError
	if !errors.As(err, &pending) || pending.id != "a1" {
		t.Fatal("pendingApprovalError not matched")
	}
}
