package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/api"
	"github.com/opencm/opencm/cli/internal/output"
)

// ---------------------------------------------------------------- packages

type pkgFile struct {
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
}

type pkgVersion struct {
	ID         string           `json:"id"`
	Version    string           `json:"version"`
	Type       string           `json:"type"`
	Status     string           `json:"status"`
	PackageRef *string          `json:"packageRef"`
	Detection  []map[string]any `json:"detection"`
	File       *pkgFile         `json:"file"`
	CreatedAt  string           `json:"createdAt"`
}

type pkg struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Publisher       string       `json:"publisher"`
	Platform        string       `json:"platform"`
	LatestVersion   *string      `json:"latestVersion"`
	ApprovedVersion *string      `json:"approvedVersion"`
	Versions        []pkgVersion `json:"versions"`
}

// resolvePackage accepts a package id or an exact name.
func resolvePackage(c *api.Client, ref string) (*pkg, error) {
	var p pkg
	if len(ref) == 36 && strings.Count(ref, "-") == 4 {
		if err := c.Do(http.MethodGet, "/packages/"+url.PathEscape(ref), nil, nil, &p); err == nil {
			return &p, nil
		}
	}
	var res struct {
		Items []pkg `json:"items"`
	}
	if err := c.Do(http.MethodGet, "/packages", url.Values{"search": {ref}}, nil, &res); err != nil {
		return nil, err
	}
	for _, x := range res.Items {
		if strings.EqualFold(x.Name, ref) {
			if err := c.Do(http.MethodGet, "/packages/"+url.PathEscape(x.ID), nil, nil, &p); err != nil {
				return nil, err
			}
			return &p, nil
		}
	}
	return nil, &api.Error{Status: 404, Message: fmt.Sprintf("package %q not found", ref)}
}

// findVersion: "" = newest approved version.
func findVersion(p *pkg, version string) (*pkgVersion, error) {
	for i := range p.Versions {
		v := &p.Versions[i]
		if (version == "" && v.Status == "approved") || (version != "" && v.Version == version) {
			return v, nil
		}
	}
	if version == "" {
		return nil, &usageError{fmt.Sprintf("package %q has no approved version", p.Name)}
	}
	return nil, &api.Error{Status: 404, Message: fmt.Sprintf("version %q of %q not found", version, p.Name)}
}

func newPackagesCmd() *cobra.Command {
	c := &cobra.Command{Use: "packages", Aliases: []string{"package", "pkg"}, Short: "Software packages (repository, versions, approval)"}

	var search, platform string
	list := &cobra.Command{
		Use:   "list",
		Short: "List packages",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{}
			if search != "" {
				q.Set("search", search)
			}
			if platform != "" {
				q.Set("platform", platform)
			}
			var res struct {
				Items []pkg `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/packages", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[pkg]{
				{Header: "ID", Value: func(p pkg) string { return p.ID }},
				{Header: "NAME", Value: func(p pkg) string { return p.Name }},
				{Header: "PLATFORM", Value: func(p pkg) string { return p.Platform }},
				{Header: "LATEST", Value: func(p pkg) string { return deref(p.LatestVersion) }},
				{Header: "APPROVED", Value: func(p pkg) string { return deref(p.ApprovedVersion) }},
			})
		},
	}
	list.Flags().StringVar(&search, "search", "", "filter by name/publisher")
	list.Flags().StringVar(&platform, "platform", "", "windows|linux|macos")

	get := &cobra.Command{
		Use:   "get <package>",
		Short: "Show a package and its versions (id or name)",
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
			p, err := resolvePackage(client, args[0])
			if err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[pkgVersion](cmd.OutOrStdout(), f, p, nil, nil)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s) – %s\n\n", p.Name, p.Platform, p.ID)
			return output.Render(cmd.OutOrStdout(), f, p, p.Versions, []output.Column[pkgVersion]{
				{Header: "VERSION", Value: func(v pkgVersion) string { return v.Version }},
				{Header: "TYPE", Value: func(v pkgVersion) string { return v.Type }},
				{Header: "STATUS", Value: func(v pkgVersion) string { return v.Status }},
				{Header: "FILE", Value: func(v pkgVersion) string {
					if v.File == nil {
						return "-"
					}
					return v.File.Name
				}},
				{Header: "SHA256", Value: func(v pkgVersion) string {
					if v.File == nil {
						return "-"
					}
					return v.File.SHA256
				}},
				{Header: "ID", Value: func(v pkgVersion) string { return v.ID }},
			})
		},
	}

	var publisher, createPlatform string
	create := &cobra.Command{
		Use:     "create <name>",
		Short:   "Create a package",
		Example: `  opencm packages create "7-Zip" --platform windows --publisher "Igor Pavlov"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var p pkg
			if err := client.Do(http.MethodPost, "/packages", nil, map[string]any{"name": args[0], "publisher": publisher, "platform": createPlatform}, &p); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), p.ID)
			return nil
		},
	}
	create.Flags().StringVar(&publisher, "publisher", "", "publisher")
	create.Flags().StringVar(&createPlatform, "platform", "windows", "windows|linux|macos")

	var vType, ref, args, uninstall, productCode, note string
	var detectSoftware, detectFile []string
	var timeout int
	addVersion := &cobra.Command{
		Use:   "add-version <package> <version>",
		Short: "Create a draft version",
		Example: `  opencm packages add-version 7-Zip 24.08 --type msi --detect-software "7-Zip*>=24.08"
  opencm packages add-version htop 3.3 --type apt --ref htop --detect-software htop
  opencm packages add-version Firefox 128 --type winget --ref Mozilla.Firefox --detect-software "Mozilla Firefox*>=128"`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, a []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			p, err := resolvePackage(client, a[0])
			if err != nil {
				return err
			}
			rules := []map[string]any{}
			for _, s := range detectSoftware {
				r, err := parseSoftwareRule(s)
				if err != nil {
					return err
				}
				rules = append(rules, r)
			}
			for _, path := range detectFile {
				rules = append(rules, map[string]any{"type": "file", "path": path})
			}
			body := map[string]any{"version": a[1], "type": vType, "installArgs": args, "uninstallCommand": uninstall, "detection": rules, "timeoutSeconds": timeout, "changeNote": note}
			if ref != "" {
				body["packageRef"] = ref
			}
			if productCode != "" {
				body["productCode"] = productCode
			}
			var v pkgVersion
			if err := client.Do(http.MethodPost, "/packages/"+url.PathEscape(p.ID)+"/versions", nil, body, &v); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", v.ID)
			fmt.Fprintf(os.Stderr, "Draft %s %s created.\n", p.Name, v.Version)
			return nil
		},
	}
	addVersion.Flags().StringVar(&vType, "type", "", "msi|exe|winget|choco|deb|rpm|apt|dnf|pkg|brew|script")
	addVersion.Flags().StringVar(&ref, "ref", "", "package id/name (winget, choco, apt, dnf, brew, deb, rpm)")
	addVersion.Flags().StringVar(&args, "args", "", "installer / package manager arguments")
	addVersion.Flags().StringVar(&uninstall, "uninstall", "", "uninstall command (PowerShell/bash)")
	addVersion.Flags().StringVar(&productCode, "product-code", "", "MSI product code {GUID}")
	addVersion.Flags().StringArrayVar(&detectSoftware, "detect-software", nil, `detection rule "<name glob>[>=|=|<version]" (repeatable)`)
	addVersion.Flags().StringArrayVar(&detectFile, "detect-file", nil, "detection rule: file exists (repeatable)")
	addVersion.Flags().IntVar(&timeout, "timeout", 3600, "timeout in seconds")
	addVersion.Flags().StringVar(&note, "note", "", "change note")
	_ = addVersion.MarkFlagRequired("type")

	upload := &cobra.Command{
		Use:     "upload <package> <version> <file>",
		Short:   "Upload the installer file of a draft version (SHA-256 is verified)",
		Example: `  opencm packages upload 7-Zip 24.08 ./7z2408-x64.msi`,
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, a []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			p, err := resolvePackage(client, a[0])
			if err != nil {
				return err
			}
			v, err := findVersion(p, a[1])
			if err != nil {
				return err
			}
			fh, err := os.Open(a[2])
			if err != nil {
				return err
			}
			defer fh.Close()
			st, err := fh.Stat()
			if err != nil {
				return err
			}
			// hash locally while streaming and compare with what the server computed
			h := sha256.New()
			var res pkgVersion
			if err := client.Upload("/packages/"+url.PathEscape(p.ID)+"/versions/"+url.PathEscape(v.ID)+"/file", url.Values{"name": {filepath.Base(a[2])}}, io.TeeReader(fh, h), st.Size(), &res); err != nil {
				return err
			}
			local := hex.EncodeToString(h.Sum(nil))
			if res.File == nil || res.File.SHA256 != local {
				return fmt.Errorf("integrity: server stored a different SHA-256 than the local file (%s) – do not approve this version", local)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", local, filepath.Base(a[2]))
			return nil
		},
	}

	versionAction := func(use, short, action string) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <package> <version>",
			Short: short,
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, a []string) error {
				client, _, _, err := session()
				if err != nil {
					return err
				}
				p, err := resolvePackage(client, a[0])
				if err != nil {
					return err
				}
				v, err := findVersion(p, a[1])
				if err != nil {
					return err
				}
				var res pkgVersion
				if err := client.Do(http.MethodPost, "/packages/"+url.PathEscape(p.ID)+"/versions/"+url.PathEscape(v.ID)+"/"+action, nil, map[string]any{}, &res); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "%s %s: %s\n", p.Name, res.Version, res.Status)
				return nil
			},
		}
	}

	var scriptAction string
	script := &cobra.Command{
		Use:   "script <package> <version>",
		Short: "Print the generated install/uninstall script",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, a []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			p, err := resolvePackage(client, a[0])
			if err != nil {
				return err
			}
			v, err := findVersion(p, a[1])
			if err != nil {
				return err
			}
			var res struct {
				Content string `json:"content"`
			}
			if err := client.Do(http.MethodGet, "/packages/"+url.PathEscape(p.ID)+"/versions/"+url.PathEscape(v.ID)+"/script", url.Values{"action": {scriptAction}}, nil, &res); err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), res.Content)
			return nil
		},
	}
	script.Flags().StringVar(&scriptAction, "action", "install", "install|uninstall")

	c.AddCommand(list, get, create, addVersion, upload,
		versionAction("approve", "Approve a draft version", "approve"),
		versionAction("retire", "Retire a version", "retire"),
		script)
	return c
}

// parseSoftwareRule: "Name*>=1.2" / "Name=1.2" / "Name<2" / "Name".
func parseSoftwareRule(s string) (map[string]any, error) {
	for _, op := range []struct{ tok, name string }{{">=", "gte"}, {"<", "lt"}, {"=", "eq"}} {
		if i := strings.Index(s, op.tok); i > 0 {
			name, ver := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+len(op.tok):])
			if ver == "" {
				return nil, &usageError{fmt.Sprintf("detection rule %q: version missing", s)}
			}
			return map[string]any{"type": "software", "name": name, "version": ver, "operator": op.name}, nil
		}
	}
	if strings.TrimSpace(s) == "" {
		return nil, &usageError{"empty detection rule"}
	}
	return map[string]any{"type": "software", "name": strings.TrimSpace(s)}, nil
}

// ---------------------------------------------------------------- deployments

type ringStats struct {
	Total          int     `json:"total"`
	Succeeded      int     `json:"succeeded"`
	Failed         int     `json:"failed"`
	Pending        int     `json:"pending"`
	Skipped        int     `json:"skipped"`
	SuccessPercent float64 `json:"successPercent"`
	Started        bool    `json:"started"`
	Finished       bool    `json:"finished"`
}

type deployment struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Kind         string  `json:"kind"`
	Action       string  `json:"action"`
	Status       string  `json:"status"`
	CurrentRing  int     `json:"currentRing"`
	PausedReason *string `json:"pausedReason"`
	CreatedAt    string  `json:"createdAt"`
	Rings        []struct {
		Name  string    `json:"name"`
		Stats ringStats `json:"stats"`
	} `json:"rings"`
	Progress *struct {
		Total     int `json:"total"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"progress"`
}

// parseRings: --ring "Test=group:IT" --ring "Alle=all" (several targets: "Pilot=group:A,device:PC1").
func parseRings(c *api.Client, specs []string, delay float64, minSuccess float64) ([]map[string]any, error) {
	if len(specs) == 0 {
		specs = []string{"Alle=all"}
	}
	rings := []map[string]any{}
	for _, s := range specs {
		name, targets, ok := strings.Cut(s, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, &usageError{fmt.Sprintf("ring %q: expected <name>=<targets>", s)}
		}
		t, err := parseTargets(c, strings.Split(targets, ","))
		if err != nil {
			return nil, err
		}
		rings = append(rings, map[string]any{"name": strings.TrimSpace(name), "targets": t, "delayHours": delay, "minSuccessPercent": minSuccess})
	}
	return rings, nil
}

func printDeploymentStart(cmd *cobra.Command, f output.Format, res map[string]any) error {
	if f != output.Table {
		return output.Render[deployment](cmd.OutOrStdout(), f, res, nil, nil)
	}
	if res["approvalRequired"] == true {
		d, _ := res["deployment"].(map[string]any)
		fmt.Fprintf(cmd.OutOrStdout(), "Deployment %v created – waiting for four-eyes approval %v\n", d["id"], res["approvalId"])
		return &pendingApprovalError{fmt.Sprint(res["approvalId"])}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Deployment %v started (ring 1 running) – opencm deployments status %v\n", res["id"], res["id"])
	return nil
}

func newDeployCmd() *cobra.Command {
	var version, action string
	var rings []string
	var delay, minSuccess float64
	c := &cobra.Command{
		Use:   "deploy <package>",
		Short: "Deploy an approved package version in rings",
		Example: `  opencm deploy 7-Zip --ring Test=group:IT --ring Pilot=group:Pilot --ring Alle=all --delay 24 --min-success 90
  opencm deploy htop --action uninstall --ring Alle=group:Linux-Server`,
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
			p, err := resolvePackage(client, args[0])
			if err != nil {
				return err
			}
			v, err := findVersion(p, version)
			if err != nil {
				return err
			}
			r, err := parseRings(client, rings, delay, minSuccess)
			if err != nil {
				return err
			}
			var res map[string]any
			if err := client.Do(http.MethodPost, "/deployments", nil, map[string]any{"kind": "package", "packageVersionId": v.ID, "action": action, "rings": r}, &res); err != nil {
				return err
			}
			return printDeploymentStart(cmd, f, res)
		},
	}
	c.Flags().StringVar(&version, "version", "", "version (default: newest approved)")
	c.Flags().StringVar(&action, "action", "install", "install|uninstall")
	c.Flags().StringArrayVar(&rings, "ring", nil, `ring "<name>=<targets>", targets: all | group:<name> | device:<hostname>, comma separated (repeatable, in order)`)
	c.Flags().Float64Var(&delay, "delay", 0, "hours between rings")
	c.Flags().Float64Var(&minSuccess, "min-success", 90, "success quota (%) for automatic promotion")
	return c
}

func newDeploymentsCmd() *cobra.Command {
	c := &cobra.Command{Use: "deployments", Aliases: []string{"deployment"}, Short: "Ring-based deployments"}
	var kind string
	list := &cobra.Command{
		Use:   "list",
		Short: "List deployments",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {"200"}}
			if kind != "" {
				q.Set("kind", kind)
			}
			var res struct {
				Items []deployment `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/deployments", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[deployment]{
				{Header: "ID", Value: func(d deployment) string { return d.ID }},
				{Header: "NAME", Value: func(d deployment) string { return d.Name }},
				{Header: "STATUS", Value: func(d deployment) string { return d.Status }},
				{Header: "RING", Value: func(d deployment) string { return strconv.Itoa(d.CurrentRing + 1) }},
				{Header: "PROGRESS", Value: func(d deployment) string {
					if d.Progress == nil {
						return "-"
					}
					return fmt.Sprintf("%d/%d ok, %d failed", d.Progress.Succeeded, d.Progress.Total, d.Progress.Failed)
				}},
				{Header: "CREATED", Value: func(d deployment) string { return d.CreatedAt }},
			})
		},
	}
	list.Flags().StringVar(&kind, "kind", "", "package|os_updates")

	status := &cobra.Command{
		Use:   "status <id>",
		Short: "Show a deployment with ring statistics",
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
			var d deployment
			if err := client.Do(http.MethodGet, "/deployments/"+url.PathEscape(args[0]), nil, nil, &d); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[deployment](cmd.OutOrStdout(), f, d, nil, nil)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s – %s\n", d.Name, d.Status)
			if d.PausedReason != nil && d.Status != "completed" {
				fmt.Fprintf(w, "  %s\n", *d.PausedReason)
			}
			for i, r := range d.Rings {
				mark := " "
				if i == d.CurrentRing {
					mark = "*"
				}
				state := "waiting"
				if r.Stats.Started {
					state = fmt.Sprintf("%d/%d ok, %d failed, %d open (%.1f %%)", r.Stats.Succeeded, r.Stats.Total-r.Stats.Skipped, r.Stats.Failed, r.Stats.Pending, r.Stats.SuccessPercent)
				}
				fmt.Fprintf(w, "%s %d. %-15s %s\n", mark, i+1, r.Name, state)
			}
			return nil
		},
	}

	control := func(action, short string) *cobra.Command {
		return &cobra.Command{
			Use:   action + " <id>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, _, _, err := session()
				if err != nil {
					return err
				}
				var d deployment
				if err := client.Do(http.MethodPost, "/deployments/"+url.PathEscape(args[0])+"/"+action, nil, map[string]any{}, &d); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "%s: %s (ring %d)\n", d.Name, d.Status, d.CurrentRing+1)
				return nil
			},
		}
	}
	c.AddCommand(list, status,
		control("promote", "Start the next ring now (ignores delay and quota)"),
		control("pause", "Stop automatic promotion"),
		control("resume", "Resume a paused deployment"),
		control("cancel", "Cancel open tasks and further rings"))
	return c
}

// ---------------------------------------------------------------- patches

type patchDevice struct {
	DeviceID       string  `json:"deviceId"`
	Hostname       string  `json:"hostname"`
	OS             string  `json:"os"`
	LastScanAt     *string `json:"lastScanAt"`
	LastScanStatus *string `json:"lastScanStatus"`
	RebootPending  bool    `json:"rebootPending"`
	Missing        int     `json:"missing"`
	Security       int     `json:"security"`
	Critical       int     `json:"critical"`
}

type devicePatch struct {
	UpdateID       string  `json:"updateId"`
	Title          string  `json:"title"`
	KB             *string `json:"kb"`
	Classification string  `json:"classification"`
	Severity       string  `json:"severity"`
	Security       bool    `json:"security"`
}

func newPatchesCmd() *cobra.Command {
	c := &cobra.Command{Use: "patches", Aliases: []string{"patch"}, Short: "Pending OS updates, scans and installation"}

	summary := &cobra.Command{
		Use:   "summary",
		Short: "Fleet patch state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var s map[string]any
			if err := client.Do(http.MethodGet, "/patches/summary", nil, nil, &s); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[patchDevice](cmd.OutOrStdout(), f, s, nil, nil)
			}
			w := cmd.OutOrStdout()
			for _, k := range []struct{ key, label string }{
				{"devices", "Devices"}, {"scanned", "Scanned"}, {"neverScanned", "Never scanned"}, {"scanFailed", "Scan failed"},
				{"upToDate", "Up to date"}, {"withSecurity", "With security updates"}, {"withCritical", "With critical updates"},
				{"rebootPending", "Reboot pending"}, {"missingTotal", "Pending updates (total)"},
			} {
				fmt.Fprintf(w, "%-26s %v\n", k.label, s[k.key])
			}
			return nil
		},
	}

	var filter string
	devices := &cobra.Command{
		Use:   "devices",
		Short: "Patch state per device",
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
				Items []patchDevice `json:"items"`
				Total int           `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/patches/devices", url.Values{"filter": {filter}, "limit": {"500"}}, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[patchDevice]{
				{Header: "HOSTNAME", Value: func(d patchDevice) string { return d.Hostname }},
				{Header: "OS", Value: func(d patchDevice) string { return d.OS }},
				{Header: "CRITICAL", Value: func(d patchDevice) string { return strconv.Itoa(d.Critical) }},
				{Header: "SECURITY", Value: func(d patchDevice) string { return strconv.Itoa(d.Security) }},
				{Header: "TOTAL", Value: func(d patchDevice) string { return strconv.Itoa(d.Missing) }},
				{Header: "REBOOT", Value: func(d patchDevice) string { return strconv.FormatBool(d.RebootPending) }},
				{Header: "LAST SCAN", Value: func(d patchDevice) string { return deref(d.LastScanAt) + " " + deref(d.LastScanStatus) }},
			})
		},
	}
	devices.Flags().StringVar(&filter, "filter", "all", "all|missing|security|reboot|never|failed")

	device := &cobra.Command{
		Use:   "device <device-id>",
		Short: "Pending updates of one device",
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
			var res struct {
				State map[string]any `json:"state"`
				Items []devicePatch  `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0])+"/patches", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[devicePatch]{
				{Header: "UPDATE", Value: func(u devicePatch) string { return u.Title }},
				{Header: "KB", Value: func(u devicePatch) string { return deref(u.KB) }},
				{Header: "CLASS", Value: func(u devicePatch) string { return u.Classification }},
				{Header: "SEVERITY", Value: func(u devicePatch) string { return u.Severity }},
				{Header: "SECURITY", Value: func(u devicePatch) string { return strconv.FormatBool(u.Security) }},
			})
		},
	}

	var scanTargets []string
	scan := &cobra.Command{
		Use:     "scan",
		Short:   "Scan devices for pending updates now",
		Example: `  opencm patches scan --target group:Server --target device:PC-0815`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			t, err := parseTargets(client, scanTargets)
			if err != nil {
				return err
			}
			var res struct {
				Devices int      `json:"devices"`
				RunIDs  []string `json:"runIds"`
			}
			if err := client.Do(http.MethodPost, "/patches/scan", nil, map[string]any{"targets": t}, &res); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Scan requested on %d device(s), runs: %s\n", res.Devices, strings.Join(res.RunIDs, ", "))
			return nil
		},
	}
	scan.Flags().StringArrayVarP(&scanTargets, "target", "t", nil, "all | group:<name> | device:<hostname> (repeatable)")

	var classification, reboot string
	var include, rings []string
	var delay, minSuccess float64
	install := &cobra.Command{
		Use:   "install",
		Short: "Install OS updates in rings (followed by a rescan)",
		Example: `  opencm patches install --classification security --ring Test=group:IT --ring Alle=all --delay 24
  opencm patches install --include KB5050001 --reboot if_required --ring Alle=group:Server`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			r, err := parseRings(client, rings, delay, minSuccess)
			if err != nil {
				return err
			}
			if include == nil {
				include = []string{}
			}
			body := map[string]any{"kind": "os_updates", "patchFilter": map[string]any{"classification": classification, "include": include, "reboot": reboot}, "rings": r}
			var res map[string]any
			if err := client.Do(http.MethodPost, "/deployments", nil, body, &res); err != nil {
				return err
			}
			return printDeploymentStart(cmd, f, res)
		},
	}
	install.Flags().StringVar(&classification, "classification", "security", "critical|security|all")
	install.Flags().StringArrayVar(&include, "include", nil, "only these update ids / KBs / package names (repeatable)")
	install.Flags().StringVar(&reboot, "reboot", "never", "never|if_required")
	install.Flags().StringArrayVar(&rings, "ring", nil, `ring "<name>=<targets>" (repeatable, in order; default "Alle=all")`)
	install.Flags().Float64Var(&delay, "delay", 0, "hours between rings")
	install.Flags().Float64Var(&minSuccess, "min-success", 90, "success quota (%) for automatic promotion")

	var exportFormat, file string
	export := &cobra.Command{
		Use:   "export",
		Short: "Export the patch state per device (CSV or JSON)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			body, err := client.Raw(http.MethodGet, "/patches/export", url.Values{"format": {exportFormat}})
			if err != nil {
				return err
			}
			defer body.Close()
			var w io.Writer = cmd.OutOrStdout()
			if file != "" && file != "-" {
				fh, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer fh.Close()
				w = fh
			}
			_, err = io.Copy(w, body)
			return err
		},
	}
	export.Flags().StringVar(&exportFormat, "format", "csv", "csv|json")
	export.Flags().StringVarP(&file, "file", "f", "", "output file (default: stdout)")

	c.AddCommand(summary, devices, device, scan, install, export)
	return c
}
