package output

import (
	"bytes"
	"strings"
	"testing"
)

type row struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

var cols = []Column[row]{
	{"NAME", func(r row) string { return r.Name }},
}

func TestRenderTable(t *testing.T) {
	var b bytes.Buffer
	rows := []row{{"alpha", 1}, {"beta", 2}}
	if err := Render(&b, Table, rows, rows, cols); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.HasPrefix(got, "NAME\nalpha\nbeta\n") {
		t.Fatalf("unexpected table output: %q", got)
	}
}

func TestRenderJSONAndYAML(t *testing.T) {
	rows := []row{{"alpha", 1}}
	var j, y bytes.Buffer
	if err := Render(&j, JSON, rows, rows, cols); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), `"name": "alpha"`) {
		t.Fatalf("json: %s", j.String())
	}
	if err := Render(&y, YAML, rows, rows, cols); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(y.String(), "name: alpha") {
		t.Fatalf("yaml: %s", y.String())
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]Format{"": Table, "JSON": JSON, "yaml": YAML} {
		if got, err := Parse(in); err != nil || got != want {
			t.Errorf("Parse(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := Parse("xml"); err == nil {
		t.Error("expected error for xml")
	}
}
