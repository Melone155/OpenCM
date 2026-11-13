// Package output renders results as table, JSON or YAML.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

type Format string

const (
	Table Format = "table"
	JSON  Format = "json"
	YAML  Format = "yaml"
)

func Parse(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case Table, "":
		return Table, nil
	case JSON:
		return JSON, nil
	case YAML:
		return YAML, nil
	}
	return "", fmt.Errorf("unknown output format %q (table|json|yaml)", s)
}

// Column extracts one table cell from a row.
type Column[T any] struct {
	Header string
	Value  func(T) string
}

// Render writes v as JSON/YAML, or rows as a table using cols.
func Render[T any](w io.Writer, f Format, v any, rows []T, cols []Column[T]) error {
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case YAML:
		// round-trip through JSON so field names match the API (json tags)
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var generic any
		if err := json.Unmarshal(b, &generic); err != nil {
			return err
		}
		return yaml.NewEncoder(w).Encode(generic)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.Header
	}
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, r := range rows {
		cells := make([]string, len(cols))
		for i, c := range cols {
			cells[i] = strings.ReplaceAll(c.Value(r), "\t", " ")
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}
