package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestSecurityQuery(t *testing.T) {
	q, err := securityQuery("no", "unencrypted", "", "", "", "windows", "")
	if err != nil || q.Get("compliant") != "false" || q.Get("encryption") != "unencrypted" || q.Get("os") != "windows" || q.Has("antivirus") {
		t.Fatalf("%v %v", q, err)
	}
	if q, _ := securityQuery("unknown", "", "", "", "", "", ""); q.Get("reported") != "false" || q.Has("compliant") {
		t.Fatalf("unknown: %v", q)
	}
	if _, err := securityQuery("maybe", "", "", "", "", "", ""); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestAssetFlagsOnlyChangedFields(t *testing.T) {
	var af assetFlags
	cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	af.register(cmd)
	if err := cmd.ParseFlags([]string{"--status", "repair", "--serial", "", "--cost", "12.5"}); err != nil {
		t.Fatal(err)
	}
	b, err := af.body(cmd, nil) // no --device → the client is not used
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 3 || b["status"] != "repair" || b["serialNumber"] != nil || b["cost"] != 12.5 {
		t.Fatalf("%#v", b)
	}
	if _, ok := b["serialNumber"]; !ok {
		t.Fatal("explicitly emptied field must be sent as null")
	}
}

func TestIsUUID(t *testing.T) {
	if !isUUID("0f8fad5b-d9cb-469f-a165-70867728950e") || isUUID("INV-0001") {
		t.Fatal("isUUID")
	}
}
