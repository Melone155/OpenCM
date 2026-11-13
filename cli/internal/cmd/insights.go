package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/output"
)

// ---------------------------------------------------------------- dashboard

func newDashboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dashboard",
		Short: "Fleet key figures (sections depend on your permissions)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var d map[string]any
			if err := client.Do(http.MethodGet, "/dashboard", nil, nil, &d); err != nil {
				return err
			}
			if f != output.Table {
				delete(d, "trends")
				return output.Render[struct{}](cmd.OutOrStdout(), f, d, nil, nil)
			}
			w := cmd.OutOrStdout()
			sections := []string{"devices", "vulnerabilities", "security", "patches", "tasks", "deployments", "approvals", "integrity", "licenses", "assets"}
			for _, s := range sections {
				m, ok := d[s].(map[string]any)
				if !ok {
					continue
				}
				keys := make([]string, 0, len(m))
				for k := range m {
					if _, nested := m[k].(map[string]any); !nested {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
				}
				fmt.Fprintf(w, "%-16s %s\n", s, strings.Join(parts, "  "))
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------- reports

type reportDef struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SourceLabel string   `json:"sourceLabel"`
	Shared      bool     `json:"shared"`
	OwnerName   *string  `json:"ownerName"`
	UpdatedAt   string   `json:"updatedAt"`
	Columns     []string `json:"columns"`
}

type reportResult struct {
	Columns []struct {
		Key   string `json:"key"`
		Label string `json:"label"`
	} `json:"columns"`
	Rows      []map[string]any `json:"rows"`
	Truncated bool             `json:"truncated"`
}

func renderResult(cmd *cobra.Command, f output.Format, r reportResult) error {
	if f != output.Table {
		return output.Render[struct{}](cmd.OutOrStdout(), f, r, nil, nil)
	}
	cols := make([]output.Column[map[string]any], 0, len(r.Columns))
	for _, c := range r.Columns {
		key := c.Key
		cols = append(cols, output.Column[map[string]any]{Header: strings.ToUpper(c.Label), Value: func(row map[string]any) string {
			if row[key] == nil {
				return "-"
			}
			return fmt.Sprint(row[key])
		}})
	}
	if err := output.Render(cmd.OutOrStdout(), f, r, r.Rows, cols); err != nil {
		return err
	}
	if r.Truncated {
		fmt.Fprintln(os.Stderr, "(result truncated – raise --limit or export as CSV)")
	}
	return nil
}

// parseReportFilter: "field op value" e.g. "os eq windows", "lastSeenAt lt 2026-11-01", "loggedOnUser empty".
// (devices.go has its own parseFilter for the device list query syntax.)
func parseReportFilter(s string) (map[string]any, error) {
	parts := strings.SplitN(strings.TrimSpace(s), " ", 3)
	if len(parts) < 2 {
		return nil, &usageError{fmt.Sprintf("filter %q: expected \"<column> <op> [value]\"", s)}
	}
	f := map[string]any{"field": parts[0], "op": parts[1]}
	if len(parts) == 3 {
		v := parts[2]
		switch {
		case parts[1] == "in":
			vals := []string{}
			for _, x := range strings.Split(v, ",") {
				vals = append(vals, strings.TrimSpace(x))
			}
			f["value"] = vals
		case v == "true" || v == "false":
			f["value"] = v == "true"
		default:
			// numbers stay numbers, except values with a leading zero ("0123" is an id, not 123)
			n, err := strconv.ParseFloat(v, 64)
			leadingZero := len(v) > 1 && v[0] == '0' && v[1] != '.'
			if err == nil && !leadingZero {
				f["value"] = n
			} else {
				f["value"] = v
			}
		}
	}
	return f, nil
}

func newReportsCmd() *cobra.Command {
	c := &cobra.Command{Use: "reports", Aliases: []string{"report"}, Short: "Reports (saved queries, ad hoc queries, CSV export)"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List own and shared reports",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				Items []reportDef `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/reports", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[reportDef]{
				{Header: "ID", Value: func(r reportDef) string { return r.ID }},
				{Header: "NAME", Value: func(r reportDef) string { return r.Name }},
				{Header: "SOURCE", Value: func(r reportDef) string { return r.SourceLabel }},
				{Header: "SHARED", Value: func(r reportDef) string { return strconv.FormatBool(r.Shared) }},
				{Header: "UPDATED", Value: func(r reportDef) string { return r.UpdatedAt }},
			})
		},
	}

	sources := &cobra.Command{
		Use:   "sources",
		Short: "Data sources and their columns",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				Items []struct {
					Key     string `json:"key"`
					Label   string `json:"label"`
					Columns []struct {
						Key  string `json:"key"`
						Type string `json:"type"`
					} `json:"columns"`
				} `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/report-sources", nil, nil, &res); err != nil {
				return err
			}
			for _, s := range res.Items {
				cols := make([]string, 0, len(s.Columns))
				for _, c := range s.Columns {
					cols = append(cols, c.Key+":"+c.Type)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-16s %s\n  %s\n", s.Key, s.Label, strings.Join(cols, ", "))
			}
			return nil
		},
	}

	var limit int
	var exportFile string
	run := &cobra.Command{
		Use:   "run <report-id>",
		Short: "Run a saved report (table/json/yaml, or CSV with --csv)",
		Example: `  opencm reports run <id>
  opencm reports run <id> --csv inventar.csv`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}}
			if exportFile != "" {
				q.Set("format", "csv")
				body, err := client.Raw(http.MethodGet, "/reports/"+url.PathEscape(args[0])+"/run", q)
				if err != nil {
					return err
				}
				defer body.Close()
				var w io.Writer = cmd.OutOrStdout()
				if exportFile != "-" {
					fh, err := os.OpenFile(exportFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
					if err != nil {
						return err
					}
					defer fh.Close()
					w = fh
				}
				_, err = io.Copy(w, body)
				return err
			}
			var r reportResult
			if err := client.Do(http.MethodGet, "/reports/"+url.PathEscape(args[0])+"/run", q, nil, &r); err != nil {
				return err
			}
			return renderResult(cmd, f, r)
		},
	}
	run.Flags().IntVar(&limit, "limit", 10000, "maximum rows (max 100000)")
	run.Flags().StringVar(&exportFile, "csv", "", "write CSV to this file (- = stdout)")

	var columns, filters []string
	var sortBy string
	var qLimit int
	query := &cobra.Command{
		Use:   "query <source>",
		Short: "Ad hoc query without saving",
		Example: `  opencm reports query devices --column hostname --column os --filter "os eq windows"
  opencm reports query software --filter "name contains firefox" --filter "version lt 130" --sort version
  opencm reports query vulnerabilities --filter "kev eq true" -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			fs := []map[string]any{}
			for _, s := range filters {
				x, err := parseReportFilter(s)
				if err != nil {
					return err
				}
				fs = append(fs, x)
			}
			if columns == nil {
				columns = []string{}
			}
			body := map[string]any{"source": args[0], "columns": columns, "filters": fs, "limit": qLimit}
			if sortBy != "" {
				dir := "asc"
				if strings.HasPrefix(sortBy, "-") {
					dir, sortBy = "desc", sortBy[1:]
				}
				body["sort"] = map[string]any{"field": sortBy, "dir": dir}
			}
			var r reportResult
			if err := client.Do(http.MethodPost, "/reports/preview", nil, body, &r); err != nil {
				return err
			}
			return renderResult(cmd, f, r)
		},
	}
	query.Flags().StringArrayVar(&columns, "column", nil, "column key (repeatable; default: the source's default columns)")
	query.Flags().StringArrayVar(&filters, "filter", nil, `filter "<column> <op> [value]", ops: eq ne contains starts gt gte lt lte in empty notempty`)
	query.Flags().StringVar(&sortBy, "sort", "", "sort column (prefix - for descending)")
	query.Flags().IntVar(&qLimit, "limit", 200, "maximum rows (max 1000; save the report for larger exports)")

	c.AddCommand(list, sources, run, query)
	return c
}

// ---------------------------------------------------------------- webhooks

type webhook struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Events       []string `json:"events"`
	Enabled      bool     `json:"enabled"`
	Secret       string   `json:"secret,omitempty"`
	LastDelivery *struct {
		Status    string  `json:"status"`
		LastError *string `json:"lastError"`
	} `json:"lastDelivery"`
}

type delivery struct {
	ID             string  `json:"id"`
	Event          string  `json:"event"`
	Status         string  `json:"status"`
	Attempts       int     `json:"attempts"`
	ResponseStatus *int    `json:"responseStatus"`
	LastError      *string `json:"lastError"`
	CreatedAt      string  `json:"createdAt"`
}

func newWebhooksCmd() *cobra.Command {
	c := &cobra.Command{Use: "webhooks", Aliases: []string{"webhook"}, Short: "Signed event notifications to other systems"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List webhooks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				Items []webhook `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/webhooks", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[webhook]{
				{Header: "ID", Value: func(h webhook) string { return h.ID }},
				{Header: "NAME", Value: func(h webhook) string { return h.Name }},
				{Header: "URL", Value: func(h webhook) string { return h.URL }},
				{Header: "EVENTS", Value: func(h webhook) string { return strings.Join(h.Events, ",") }},
				{Header: "ENABLED", Value: func(h webhook) string { return strconv.FormatBool(h.Enabled) }},
				{Header: "LAST", Value: func(h webhook) string {
					if h.LastDelivery == nil {
						return "-"
					}
					return h.LastDelivery.Status + " " + deref(h.LastDelivery.LastError)
				}},
			})
		},
	}

	var events []string
	create := &cobra.Command{
		Use:     "create <name> <url>",
		Short:   "Create a webhook; prints the signing secret once",
		Example: `  opencm webhooks create Ticketsystem https://tickets.example.org/hooks/opencm --event security.integrity_violation --event deployment.paused`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			if len(events) == 0 {
				events = []string{"*"}
			}
			var h webhook
			if err := client.Do(http.MethodPost, "/webhooks", nil, map[string]any{"name": args[0], "url": args[1], "events": events}, &h); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), h.Secret)
			fmt.Fprintf(os.Stderr, "Webhook %s created – store the secret now, it is not shown again.\n", h.ID)
			return nil
		},
	}
	create.Flags().StringArrayVar(&events, "event", nil, "event name (repeatable; default: all)")

	test := &cobra.Command{
		Use:   "test <id>",
		Short: "Send a test event now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var d delivery
			if err := client.Do(http.MethodPost, "/webhooks/"+url.PathEscape(args[0])+"/test", nil, map[string]any{}, &d); err != nil {
				return err
			}
			if d.Status != "succeeded" {
				return fmt.Errorf("test delivery failed: %s", deref(d.LastError))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "delivered (HTTP %d)\n", *d.ResponseStatus)
			return nil
		},
	}

	var status string
	deliveries := &cobra.Command{
		Use:   "deliveries <id>",
		Short: "Delivery log of a webhook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {"100"}}
			if status != "" {
				q.Set("status", status)
			}
			var res struct {
				Items []delivery `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/webhooks/"+url.PathEscape(args[0])+"/deliveries", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[delivery]{
				{Header: "TIME", Value: func(d delivery) string { return d.CreatedAt }},
				{Header: "EVENT", Value: func(d delivery) string { return d.Event }},
				{Header: "STATUS", Value: func(d delivery) string { return d.Status }},
				{Header: "ATTEMPTS", Value: func(d delivery) string { return strconv.Itoa(d.Attempts) }},
				{Header: "ERROR", Value: func(d delivery) string { return deref(d.LastError) }},
				{Header: "ID", Value: func(d delivery) string { return d.ID }},
			})
		},
	}
	deliveries.Flags().StringVar(&status, "status", "", "pending|succeeded|failed")

	redeliver := &cobra.Command{
		Use:   "redeliver <delivery-id>",
		Short: "Queue a delivery again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			return client.Do(http.MethodPost, "/webhook-deliveries/"+url.PathEscape(args[0])+"/redeliver", nil, map[string]any{}, nil)
		},
	}

	c.AddCommand(list, create, test, deliveries, redeliver)
	return c
}

// ---------------------------------------------------------------- software licenses

type softwareLicense struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Vendor      string  `json:"vendor"`
	Pattern     string  `json:"softwarePattern"`
	Seats       int     `json:"seats"`
	Used        int     `json:"used"`
	Available   int     `json:"available"`
	Overused    bool    `json:"overused"`
	ExpiresAt   *string `json:"expiresAt"`
	ExpiringSon bool    `json:"expiringSoon"`
}

func newLicensesCmd() *cobra.Command {
	c := &cobra.Command{Use: "licenses", Aliases: []string{"license"}, Short: "Software license management (licenses your organisation owns for third-party software)"}
	list := &cobra.Command{
		Use:   "list",
		Short: "Licenses with usage from the inventory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				Items []softwareLicense `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/licenses", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[softwareLicense]{
				{Header: "NAME", Value: func(l softwareLicense) string { return l.Name }},
				{Header: "PATTERN", Value: func(l softwareLicense) string { return l.Pattern }},
				{Header: "USED", Value: func(l softwareLicense) string { return fmt.Sprintf("%d/%d", l.Used, l.Seats) }},
				{Header: "OVERUSED", Value: func(l softwareLicense) string { return strconv.FormatBool(l.Overused) }},
				{Header: "EXPIRES", Value: func(l softwareLicense) string { return deref(l.ExpiresAt) }},
				{Header: "ID", Value: func(l softwareLicense) string { return l.ID }},
			})
		},
	}
	var vendor, publisher, expires string
	var seats int
	create := &cobra.Command{
		Use:     "create <name> <software-pattern>",
		Short:   "Record a license",
		Example: `  opencm licenses create "Microsoft 365 Apps" "Microsoft 365 Apps*" --seats 120 --expires 2027-06-30`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			body := map[string]any{"name": args[0], "softwarePattern": args[1], "seats": seats, "vendor": vendor}
			if publisher != "" {
				body["publisherPattern"] = publisher
			}
			if expires != "" {
				body["expiresAt"] = expires
			}
			var l softwareLicense
			if err := client.Do(http.MethodPost, "/licenses", nil, body, &l); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %d of %d in use\n", l.Name, l.Used, l.Seats)
			return nil
		},
	}
	create.Flags().IntVar(&seats, "seats", 1, "number of licenses owned")
	create.Flags().StringVar(&vendor, "vendor", "", "vendor")
	create.Flags().StringVar(&publisher, "publisher", "", "publisher glob (optional)")
	create.Flags().StringVar(&expires, "expires", "", "expiry date YYYY-MM-DD")
	c.AddCommand(list, create)
	return c
}
