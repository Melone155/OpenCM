package cmd

import (
	"reflect"
	"testing"
)

func TestParseReportFilter(t *testing.T) {
	cases := map[string]map[string]any{
		"os eq windows":          {"field": "os", "op": "eq", "value": "windows"},
		"cvss gte 9":             {"field": "cvss", "op": "gte", "value": float64(9)},
		"kev eq true":            {"field": "kev", "op": "eq", "value": true},
		"loggedOnUser empty":     {"field": "loggedOnUser", "op": "empty"},
		"name contains Office 3": {"field": "name", "op": "contains", "value": "Office 3"},
		"serialNumber eq 0123":   {"field": "serialNumber", "op": "eq", "value": "0123"},
		"hostname in a, b":       {"field": "hostname", "op": "in", "value": []string{"a", "b"}},
	}
	for in, want := range cases {
		got, err := parseReportFilter(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseReportFilter(%q) = %#v, %v; want %#v", in, got, err, want)
		}
	}
	if _, err := parseReportFilter("onlyfield"); err == nil {
		t.Error("expected error for missing operator")
	}
}
