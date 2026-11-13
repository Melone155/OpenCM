package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/output"
)

type vuln struct {
	CveID           string   `json:"cveId"`
	Description     string   `json:"description"`
	CvssScore       *float64 `json:"cvssScore"`
	CvssSeverity    *string  `json:"cvssSeverity"`
	Kev             bool     `json:"kev"`
	KevDueDate      *string  `json:"kevDueDate"`
	Epss            *float64 `json:"epss"`
	AffectedDevices int      `json:"affectedDevices,omitempty"`
	Products        []string `json:"products,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	AcceptedAt      *string  `json:"acceptedAt"`
	SoftwareName    string   `json:"softwareName,omitempty"`
	SoftwareVersion string   `json:"softwareVersion,omitempty"`
}

func score(v *float64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatFloat(*v, 'f', 1, 64)
}

func percent(v *float64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatFloat(*v*100, 'f', 1, 64) + "%"
}

func kevMark(v vuln) string {
	if v.Kev {
		return "KEV"
	}
	return ""
}

var vulnCols = []output.Column[vuln]{
	{Header: "CVE", Value: func(v vuln) string { return v.CveID }},
	{Header: "SEVERITY", Value: func(v vuln) string { return deref(v.CvssSeverity) }},
	{Header: "CVSS", Value: func(v vuln) string { return score(v.CvssScore) }},
	{Header: "EPSS", Value: func(v vuln) string { return percent(v.Epss) }},
	{Header: "KEV", Value: kevMark},
	{Header: "DEVICES", Value: func(v vuln) string { return strconv.Itoa(v.AffectedDevices) }},
	{Header: "PRODUCTS", Value: func(v vuln) string { return strings.Join(v.Products, ",") }},
	{Header: "CONFIDENCE", Value: func(v vuln) string { return v.Confidence }},
}

func newCveCmd() *cobra.Command {
	c := &cobra.Command{Use: "cve", Aliases: []string{"vulnerabilities", "vulns"}, Short: "Vulnerabilities (NVD, CISA KEV, EPSS)"}

	var severity, confidence, device, search string
	var kev, accepted bool
	var limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List CVEs with open findings, ordered by risk",
		Example: `  opencm cve list --severity critical
  opencm cve list --kev -o json
  opencm cve list --device PC-0815 --severity high,critical`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}}
			if severity != "" {
				q.Set("severity", strings.ToUpper(severity))
			}
			if confidence != "" {
				q.Set("confidence", strings.ToLower(confidence))
			}
			if search != "" {
				q.Set("search", search)
			}
			if kev {
				q.Set("kev", "true")
			}
			if accepted {
				q.Set("includeAccepted", "true")
			}
			if device != "" {
				t, err := parseTargets(client, []string{"device:" + device})
				if err != nil {
					return err
				}
				q.Set("deviceId", t.DeviceIDs[0])
			}
			var res struct {
				Items []vuln `json:"items"`
				Total int    `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/vulnerabilities", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, vulnCols)
		},
	}
	list.Flags().StringVar(&severity, "severity", "", "comma separated: critical,high,medium,low")
	list.Flags().StringVar(&confidence, "confidence", "", "comma separated: high,medium,low")
	list.Flags().StringVar(&device, "device", "", "only this device (hostname or id)")
	list.Flags().StringVar(&search, "search", "", "CVE id, product or software name")
	list.Flags().BoolVar(&kev, "kev", false, "only actively exploited (CISA KEV)")
	list.Flags().BoolVar(&accepted, "include-accepted", false, "include accepted risks")
	list.Flags().IntVar(&limit, "limit", 100, "number of CVEs (max 500)")

	get := &cobra.Command{
		Use:   "get <CVE-ID>",
		Short: "Show a CVE and the affected devices",
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
			var d struct {
				vuln
				CvssVector *string `json:"cvssVector"`
				Refs       []struct {
					URL string `json:"url"`
				} `json:"refs"`
				Affected []struct {
					Hostname        string `json:"hostname"`
					SoftwareName    string `json:"softwareName"`
					SoftwareVersion string `json:"softwareVersion"`
					Confidence      string `json:"confidence"`
					Status          string `json:"status"`
				} `json:"affected"`
			}
			if err := client.Do(http.MethodGet, "/vulnerabilities/"+url.PathEscape(strings.ToUpper(args[0])), nil, nil, &d); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[vuln](cmd.OutOrStdout(), f, d, nil, nil)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s  %s %s  EPSS %s %s\n%s\n", d.CveID, deref(d.CvssSeverity), score(d.CvssScore), percent(d.Epss), kevMark(d.vuln), d.Description)
			if d.Kev {
				fmt.Fprintf(w, "Actively exploited (CISA KEV), due %s\n", deref(d.KevDueDate))
			}
			if d.AcceptedAt != nil {
				fmt.Fprintf(w, "Risk accepted at %s\n", *d.AcceptedAt)
			}
			fmt.Fprintln(w, "\nAffected:")
			for _, a := range d.Affected {
				fmt.Fprintf(w, "  %-6s %-24s %s %s (%s)\n", a.Status, a.Hostname, a.SoftwareName, a.SoftwareVersion, a.Confidence)
			}
			if len(d.Refs) > 0 {
				fmt.Fprintln(w, "\nReferences:")
				for i, r := range d.Refs {
					if i >= 5 {
						break
					}
					fmt.Fprintf(w, "  %s\n", r.URL)
				}
			}
			return nil
		},
	}

	summary := &cobra.Command{
		Use:   "summary",
		Short: "Open findings by severity and feed status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var s struct {
				OpenCves        int `json:"openCves"`
				AffectedDevices int `json:"affectedDevices"`
				Kev             struct {
					Cves    int `json:"cves"`
					Devices int `json:"devices"`
					Overdue int `json:"overdue"`
				} `json:"kev"`
				BySeverity map[string]struct {
					Cves    int `json:"cves"`
					Devices int `json:"devices"`
				} `json:"bySeverity"`
				Mirror struct {
					Cves int `json:"cves"`
				} `json:"mirror"`
				Feeds []struct {
					Name          string  `json:"name"`
					LastSuccessAt *string `json:"lastSuccessAt"`
					Error         *string `json:"error"`
				} `json:"feeds"`
			}
			if err := client.Do(http.MethodGet, "/vulnerabilities/summary", nil, nil, &s); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[struct{}](cmd.OutOrStdout(), f, s, nil, nil)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%d open CVEs on %d devices; %d actively exploited (%d overdue)\n", s.OpenCves, s.AffectedDevices, s.Kev.Cves, s.Kev.Overdue)
			for _, k := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				fmt.Fprintf(w, "  %-9s %4d CVEs  %4d devices\n", k, s.BySeverity[k].Cves, s.BySeverity[k].Devices)
			}
			fmt.Fprintf(w, "NVD mirror: %d CVEs\n", s.Mirror.Cves)
			for _, fd := range s.Feeds {
				fmt.Fprintf(w, "  feed %-10s last success %s %s\n", fd.Name, deref(fd.LastSuccessAt), deref(fd.Error))
			}
			return nil
		},
	}

	var reason string
	var undo bool
	accept := &cobra.Command{
		Use:   "accept <CVE-ID>",
		Short: "Accept the risk of a CVE fleet-wide (--undo to revert)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !undo && reason == "" {
				return &usageError{"--reason is required"}
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			body := map[string]any{"accepted": !undo}
			if !undo {
				body["reason"] = reason
			}
			if err := client.Do(http.MethodPatch, "/vulnerabilities/"+url.PathEscape(strings.ToUpper(args[0])), nil, body, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%s updated\n", strings.ToUpper(args[0]))
			return nil
		},
	}
	accept.Flags().StringVar(&reason, "reason", "", "justification (required)")
	accept.Flags().BoolVar(&undo, "undo", false, "revoke the acceptance")

	var scriptID string
	var params []string
	var runNow bool
	remediate := &cobra.Command{
		Use:     "remediate <CVE-ID>",
		Short:   "Create a remediation job (approved script) for all affected devices",
		Example: `  opencm cve remediate CVE-2024-1234 --script <script-id> --param PackageId=Mozilla.Firefox --run`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if scriptID == "" {
				return &usageError{"--script is required"}
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var s script
			if err := client.Do(http.MethodGet, "/scripts/"+url.PathEscape(scriptID), nil, nil, &s); err != nil {
				return err
			}
			if s.ApprovedVersion == nil {
				return &usageError{fmt.Sprintf("script %q has no approved version", s.Name)}
			}
			var defs []scriptParam
			for _, v := range s.Versions {
				if v.Version == *s.ApprovedVersion {
					defs = v.Parameters
				}
			}
			p, err := parseParams(defs, params)
			if err != nil {
				return err
			}
			var res struct {
				JobID   string  `json:"jobId"`
				RunID      *string `json:"runId"`
				ApprovalID *string `json:"approvalId"`
				Devices    int     `json:"devices"`
			}
			if err := client.Do(http.MethodPost, "/vulnerabilities/"+url.PathEscape(strings.ToUpper(args[0]))+"/remediation", nil, map[string]any{"scriptId": scriptID, "params": p, "runNow": runNow}, &res); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Job %s created for %d device(s)", res.JobID, res.Devices)
			if res.RunID != nil {
				fmt.Fprintf(cmd.OutOrStdout(), ", run %s started (opencm jobs status %s --watch)", *res.RunID, *res.RunID)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			if res.ApprovalID != nil {
				return &pendingApprovalError{*res.ApprovalID}
			}
			return nil
		},
	}
	remediate.Flags().StringVar(&scriptID, "script", "", "approved script id")
	remediate.Flags().StringArrayVar(&params, "param", nil, "parameter name=value (repeatable)")
	remediate.Flags().BoolVar(&runNow, "run", false, "start the job immediately")

	var feeds []string
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Request a feed sync (NVD, KEV, EPSS) and full re-evaluation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			body := map[string]any{}
			if len(feeds) > 0 {
				body["feeds"] = feeds
			}
			if err := client.Do(http.MethodPost, "/vulnerability-feeds/sync", nil, body, nil); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Sync requested – the worker picks it up within a minute.")
			return nil
		},
	}
	syncCmd.Flags().StringSliceVar(&feeds, "feed", nil, "nvd,kev,epss (default: all)")

	c.AddCommand(list, get, summary, accept, remediate, syncCmd)
	return c
}

func newSoftwareCmd() *cobra.Command {
	var search, mapping string
	var limit int
	c := &cobra.Command{
		Use:   "software",
		Short: "Software across all devices and its CPE mapping",
		Example: `  opencm software --mapping unmapped
  opencm software --search firefox -o json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}, "mapping": {mapping}}
			if search != "" {
				q.Set("search", search)
			}
			type mappingT struct {
				Vendor     string `json:"vendor"`
				Product    string `json:"product"`
				Method     string `json:"method"`
				Confidence string `json:"confidence"`
				Ignored    bool   `json:"ignored"`
			}
			type sw struct {
				Name        string    `json:"name"`
				Publisher   string    `json:"publisher"`
				Source      string    `json:"source"`
				DeviceCount int       `json:"deviceCount"`
				Versions    []string  `json:"versions"`
				Mapping     *mappingT `json:"mapping"`
			}
			var res struct {
				Items []sw `json:"items"`
				Total int  `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/software", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[sw]{
				{Header: "NAME", Value: func(s sw) string { return s.Name }},
				{Header: "PUBLISHER", Value: func(s sw) string { return s.Publisher }},
				{Header: "DEVICES", Value: func(s sw) string { return strconv.Itoa(s.DeviceCount) }},
				{Header: "VERSIONS", Value: func(s sw) string { return strings.Join(s.Versions, ",") }},
				{Header: "CPE", Value: func(s sw) string {
					switch {
					case s.Mapping == nil:
						return "-"
					case s.Mapping.Ignored:
						return "(ignored)"
					}
					return fmt.Sprintf("%s:%s (%s)", s.Mapping.Vendor, s.Mapping.Product, s.Mapping.Method)
				}},
			})
		},
	}
	c.Flags().StringVar(&search, "search", "", "name or publisher")
	c.Flags().StringVar(&mapping, "mapping", "all", "all|mapped|unmapped|ignored")
	c.Flags().IntVar(&limit, "limit", 200, "number of entries (max 500)")
	return c
}
