package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/api"
	"github.com/opencm/opencm/cli/internal/output"
)

// ---------------------------------------------------------------- security status

type issue struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

type securityRow struct {
	DeviceID   string  `json:"deviceId"`
	Hostname   string  `json:"hostname"`
	OS         string  `json:"os"`
	Reported   bool    `json:"reported"`
	Compliant  bool    `json:"compliant"`
	Encryption string  `json:"encryption"`
	Antivirus  string  `json:"antivirus"`
	Firewall   string  `json:"firewall"`
	SecureBoot *bool   `json:"secureBoot"`
	TPM        string  `json:"tpm"`
	Issues     []issue `json:"issues"`
}

func issueLabels(is []issue) string {
	if len(is) == 0 {
		return "-"
	}
	out := make([]string, len(is))
	for i, x := range is {
		out[i] = x.Label
	}
	return strings.Join(out, "; ")
}

func compliance(r securityRow) string {
	switch {
	case !r.Reported:
		return "no data"
	case r.Compliant:
		return "ok"
	default:
		return "NOT OK"
	}
}

// securityQuery maps CLI flags to query parameters of GET /security-status.
func securityQuery(compliantFlag, encryption, antivirus, firewall, issueCode, osName, search string) (url.Values, error) {
	q := url.Values{}
	switch compliantFlag {
	case "":
	case "yes", "true":
		q.Set("compliant", "true")
	case "no", "false":
		q.Set("compliant", "false")
	case "unknown":
		q.Set("reported", "false")
	default:
		return nil, &usageError{fmt.Sprintf("--compliant %q: expected yes, no or unknown", compliantFlag)}
	}
	for k, v := range map[string]string{"encryption": encryption, "antivirus": antivirus, "firewall": firewall, "issue": issueCode, "os": osName, "search": search} {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q, nil
}

func newSecurityCmd() *cobra.Command {
	c := &cobra.Command{Use: "security", Short: "Security status of devices (disk encryption, antivirus, firewall, Secure Boot, TPM)"}

	var compliantFlag, encryption, antivirus, firewall, issueCode, osName, search, csvFile string
	var limit int
	status := &cobra.Command{
		Use:   "status",
		Short: "Fleet overview, problems first",
		Example: `  opencm security status
  opencm security status --compliant no
  opencm security status --encryption unencrypted --os windows
  opencm security status --issue av_outdated -o json
  opencm security status --csv sicherheitsstatus.csv`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q, err := securityQuery(compliantFlag, encryption, antivirus, firewall, issueCode, osName, search)
			if err != nil {
				return err
			}
			if csvFile != "" {
				q.Set("format", "csv")
				return download(cmd, client, "/security-status", q, csvFile)
			}
			q.Set("limit", strconv.Itoa(limit))
			var res struct {
				Summary struct {
					Devices      int `json:"devices"`
					Reported     int `json:"reported"`
					Compliant    int `json:"compliant"`
					Noncompliant int `json:"noncompliant"`
				} `json:"summary"`
				Items []securityRow `json:"items"`
				Total int           `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/security-status", q, nil, &res); err != nil {
				return err
			}
			if f == output.Table {
				s := res.Summary
				fmt.Fprintf(os.Stderr, "%d devices: %d compliant, %d not compliant, %d without data\n", s.Devices, s.Compliant, s.Noncompliant, s.Devices-s.Reported)
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[securityRow]{
				{Header: "DEVICE", Value: func(r securityRow) string { return r.Hostname }},
				{Header: "OS", Value: func(r securityRow) string { return r.OS }},
				{Header: "STATUS", Value: compliance},
				{Header: "ENCRYPTION", Value: func(r securityRow) string { return r.Encryption }},
				{Header: "ANTIVIRUS", Value: func(r securityRow) string { return r.Antivirus }},
				{Header: "FIREWALL", Value: func(r securityRow) string { return r.Firewall }},
				{Header: "ISSUES", Value: func(r securityRow) string { return issueLabels(r.Issues) }},
			})
		},
	}
	status.Flags().StringVar(&compliantFlag, "compliant", "", "yes|no|unknown (unknown = agent has not reported a status)")
	status.Flags().StringVar(&encryption, "encryption", "", "encrypted|partial|unencrypted|unknown")
	status.Flags().StringVar(&antivirus, "antivirus", "", "ok|outdated|disabled|missing|unknown")
	status.Flags().StringVar(&firewall, "firewall", "", "on|partial|off|unknown")
	status.Flags().StringVar(&issueCode, "issue", "", "issue code, e.g. unencrypted, encryption_suspended, av_outdated, firewall_off")
	status.Flags().StringVar(&osName, "os", "", "windows|linux|macos")
	status.Flags().StringVar(&search, "search", "", "host name or user")
	status.Flags().IntVar(&limit, "limit", 200, "maximum rows (max 500)")
	status.Flags().StringVar(&csvFile, "csv", "", "write CSV to this file (- = stdout)")

	device := &cobra.Command{
		Use:   "device <device-id>",
		Short: "Security details of one device (as reported by the agent)",
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
			var d map[string]any
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0])+"/security", nil, nil, &d); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[struct{}](cmd.OutOrStdout(), f, d, nil, nil)
			}
			w := cmd.OutOrStdout()
			for _, k := range []string{"compliant", "encryption", "antivirus", "firewall", "secureBoot", "tpm", "collectedAt"} {
				fmt.Fprintf(w, "%-12s %v\n", k, d[k])
			}
			if is, ok := d["issues"].([]any); ok {
				for _, x := range is {
					if m, ok := x.(map[string]any); ok {
						fmt.Fprintf(w, "  ! %v\n", m["label"])
					}
				}
			}
			return nil
		},
	}

	c.AddCommand(status, device)
	return c
}

// download writes a raw (CSV) response to a file or stdout.
func download(cmd *cobra.Command, client *api.Client, path string, q url.Values, file string) error {
	body, err := client.Raw(http.MethodGet, path, q)
	if err != nil {
		return err
	}
	defer body.Close()
	var w io.Writer = cmd.OutOrStdout()
	if file != "-" {
		fh, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}
	_, err = io.Copy(w, body)
	return err
}

// ---------------------------------------------------------------- assets

type asset struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Status          string   `json:"status"`
	Manufacturer    string   `json:"manufacturer"`
	Model           string   `json:"model"`
	SerialNumber    *string  `json:"serialNumber"`
	InventoryNumber *string  `json:"inventoryNumber"`
	Location        string   `json:"location"`
	AssignedTo      string   `json:"assignedTo"`
	IPAddress       *string  `json:"ipAddress"`
	MACAddress      *string  `json:"macAddress"`
	PurchaseDate    *string  `json:"purchaseDate"`
	WarrantyUntil   *string  `json:"warrantyUntil"`
	Cost            *float64 `json:"cost"`
	DeviceID        *string  `json:"deviceId"`
	DeviceHostname  *string  `json:"deviceHostname"`
	Notes           string   `json:"notes"`
}

var assetColumns = []output.Column[asset]{
	{Header: "NAME", Value: func(a asset) string { return a.Name }},
	{Header: "TYPE", Value: func(a asset) string { return a.Type }},
	{Header: "STATUS", Value: func(a asset) string { return a.Status }},
	{Header: "INVENTORY", Value: func(a asset) string { return deref(a.InventoryNumber) }},
	{Header: "SERIAL", Value: func(a asset) string { return deref(a.SerialNumber) }},
	{Header: "LOCATION", Value: func(a asset) string { return orDash(a.Location) }},
	{Header: "ASSIGNED", Value: func(a asset) string { return orDash(a.AssignedTo) }},
	{Header: "WARRANTY", Value: func(a asset) string { return deref(a.WarrantyUntil) }},
	{Header: "DEVICE", Value: func(a asset) string { return deref(a.DeviceHostname) }},
	{Header: "ID", Value: func(a asset) string { return a.ID }},
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func isUUID(s string) bool { return len(s) == 36 && strings.Count(s, "-") == 4 }

// resolveDeviceID accepts a device id or an exact host name.
func resolveDeviceID(c *api.Client, ref string) (string, error) {
	if isUUID(ref) {
		return ref, nil
	}
	var res struct {
		Items []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"items"`
	}
	if err := c.Do(http.MethodGet, "/devices", url.Values{"search": {ref}, "limit": {"50"}}, nil, &res); err != nil {
		return "", err
	}
	for _, d := range res.Items {
		if strings.EqualFold(d.Hostname, ref) {
			return d.ID, nil
		}
	}
	return "", &api.Error{Status: 404, Message: fmt.Sprintf("device %q not found", ref)}
}

// resolveAssetID accepts an asset id or an exact inventory number.
func resolveAssetID(c *api.Client, ref string) (string, error) {
	if isUUID(ref) {
		return ref, nil
	}
	var res struct {
		Items []asset `json:"items"`
	}
	if err := c.Do(http.MethodGet, "/assets", url.Values{"search": {ref}, "limit": {"100"}}, nil, &res); err != nil {
		return "", err
	}
	for _, a := range res.Items {
		if a.InventoryNumber != nil && strings.EqualFold(*a.InventoryNumber, ref) {
			return a.ID, nil
		}
	}
	return "", &api.Error{Status: 404, Message: fmt.Sprintf("asset %q not found (use the id or the inventory number)", ref)}
}

// assetFlags collects the editable fields; only flags the user set end up in the request body.
type assetFlags struct {
	typ, status, manufacturer, model, serial, inventory, location, assigned, ip, mac, purchased, warranty, device, notes string
	cost                                                                                                                float64
}

func (af *assetFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&af.typ, "type", "", "computer|notebook|server|monitor|printer|phone|tablet|network|peripheral|other")
	fl.StringVar(&af.status, "status", "", "in_stock|in_use|repair|retired")
	fl.StringVar(&af.manufacturer, "manufacturer", "", "manufacturer")
	fl.StringVar(&af.model, "model", "", "model")
	fl.StringVar(&af.serial, "serial", "", "serial number")
	fl.StringVar(&af.inventory, "inventory", "", "inventory number (unique)")
	fl.StringVar(&af.location, "location", "", "location / room")
	fl.StringVar(&af.assigned, "assigned-to", "", "person the asset is assigned to")
	fl.StringVar(&af.ip, "ip", "", "IP address")
	fl.StringVar(&af.mac, "mac", "", "MAC address")
	fl.StringVar(&af.purchased, "purchased", "", "purchase date YYYY-MM-DD")
	fl.StringVar(&af.warranty, "warranty", "", "warranty end YYYY-MM-DD")
	fl.Float64Var(&af.cost, "cost", 0, "cost")
	fl.StringVar(&af.device, "device", "", "linked managed device (host name or id; \"none\" removes the link)")
	fl.StringVar(&af.notes, "notes", "", "notes")
}

// body builds the JSON body from the flags that were set explicitly. Empty values clear optional fields.
func (af *assetFlags) body(cmd *cobra.Command, c *api.Client) (map[string]any, error) {
	b := map[string]any{}
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	set := func(flag, key string, v any) {
		if cmd.Flags().Changed(flag) {
			b[key] = v
		}
	}
	set("type", "type", af.typ)
	set("status", "status", af.status)
	set("manufacturer", "manufacturer", af.manufacturer)
	set("model", "model", af.model)
	set("serial", "serialNumber", nullable(af.serial))
	set("inventory", "inventoryNumber", nullable(af.inventory))
	set("location", "location", af.location)
	set("assigned-to", "assignedTo", af.assigned)
	set("ip", "ipAddress", nullable(af.ip))
	set("mac", "macAddress", nullable(af.mac))
	set("purchased", "purchaseDate", nullable(af.purchased))
	set("warranty", "warrantyUntil", nullable(af.warranty))
	set("cost", "cost", af.cost)
	set("notes", "notes", af.notes)
	if cmd.Flags().Changed("device") {
		if af.device == "" || af.device == "none" {
			b["deviceId"] = nil
		} else {
			id, err := resolveDeviceID(c, af.device)
			if err != nil {
				return nil, err
			}
			b["deviceId"] = id
		}
	}
	return b, nil
}

func newAssetsCmd() *cobra.Command {
	c := &cobra.Command{Use: "assets", Aliases: []string{"asset"}, Short: "Assets without an agent (monitors, printers, phones, network gear …)"}

	var search, typ, status, device, csvFile string
	var warrantyDays, limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List assets",
		Example: `  opencm assets list --type monitor
  opencm assets list --warranty-days 30
  opencm assets list --device PC-0815
  opencm assets list --csv assets.csv`,
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
			for k, v := range map[string]string{"search": search, "type": typ, "status": status} {
				if v != "" {
					q.Set(k, v)
				}
			}
			if cmd.Flags().Changed("warranty-days") {
				q.Set("warrantyDays", strconv.Itoa(warrantyDays))
				q.Set("sort", "warrantyUntil")
			}
			if device != "" {
				id, err := resolveDeviceID(client, device)
				if err != nil {
					return err
				}
				q.Set("deviceId", id)
			}
			if csvFile != "" {
				q.Set("format", "csv")
				return download(cmd, client, "/assets", q, csvFile)
			}
			q.Set("limit", strconv.Itoa(limit))
			var res struct {
				Items []asset `json:"items"`
				Total int     `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/assets", q, nil, &res); err != nil {
				return err
			}
			if err := output.Render(cmd.OutOrStdout(), f, res, res.Items, assetColumns); err != nil {
				return err
			}
			if f == output.Table && res.Total > len(res.Items) {
				fmt.Fprintf(os.Stderr, "(%d of %d shown – raise --limit or export with --csv)\n", len(res.Items), res.Total)
			}
			return nil
		},
	}
	list.Flags().StringVar(&search, "search", "", "name, serial/inventory number, model, person, location, IP, device")
	list.Flags().StringVar(&typ, "type", "", "asset type")
	list.Flags().StringVar(&status, "status", "", "in_stock|in_use|repair|retired")
	list.Flags().StringVar(&device, "device", "", "only assets linked to this device (host name or id)")
	list.Flags().IntVar(&warrantyDays, "warranty-days", 30, "only assets whose warranty ends within N days (incl. expired)")
	list.Flags().IntVar(&limit, "limit", 200, "maximum rows (max 500)")
	list.Flags().StringVar(&csvFile, "csv", "", "export as CSV (re-importable) to this file (- = stdout)")

	show := &cobra.Command{
		Use:   "show <id|inventory-number>",
		Short: "Show one asset",
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
			id, err := resolveAssetID(client, args[0])
			if err != nil {
				return err
			}
			var a asset
			if err := client.Do(http.MethodGet, "/assets/"+url.PathEscape(id), nil, nil, &a); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, a, []asset{a}, assetColumns)
		},
	}

	var cf assetFlags
	create := &cobra.Command{
		Use:     "create <name>",
		Short:   "Record an asset",
		Example: `  opencm assets create "Monitor Empfang" --type monitor --inventory INV-0001 --serial MON-1 --device PC-0815 --warranty 2028-03-31`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			b, err := cf.body(cmd, client)
			if err != nil {
				return err
			}
			b["name"] = args[0]
			var a asset
			if err := client.Do(http.MethodPost, "/assets", nil, b, &a); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), a.ID)
			return nil
		},
	}
	cf.register(create)

	var uf assetFlags
	var newName string
	update := &cobra.Command{
		Use:     "update <id|inventory-number>",
		Short:   "Change fields of an asset (only the given flags)",
		Example: `  opencm assets update INV-0001 --status repair --notes "Display flackert"`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			id, err := resolveAssetID(client, args[0])
			if err != nil {
				return err
			}
			b, err := uf.body(cmd, client)
			if err != nil {
				return err
			}
			if newName != "" {
				b["name"] = newName
			}
			if len(b) == 0 {
				return &usageError{"nothing to change – pass at least one field flag"}
			}
			return client.Do(http.MethodPatch, "/assets/"+url.PathEscape(id), nil, b, nil)
		},
	}
	uf.register(update)
	update.Flags().StringVar(&newName, "name", "", "new name")

	del := &cobra.Command{
		Use:   "delete <id|inventory-number>",
		Short: "Delete an asset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			id, err := resolveAssetID(client, args[0])
			if err != nil {
				return err
			}
			return client.Do(http.MethodDelete, "/assets/"+url.PathEscape(id), nil, nil, nil)
		},
	}

	var dryRun bool
	imp := &cobra.Command{
		Use:   "import <file.csv>",
		Short: "Import assets from CSV (Excel \";\" or \",\"; matched by inventory number, then serial number)",
		Long: `Columns (English keys or German names): name/Bezeichnung (required), type/Typ, status, manufacturer/Hersteller,
model/Modell, serialNumber/Seriennummer, inventoryNumber/Inventarnummer, location/Standort, assignedTo/Benutzer,
ipAddress/IP, macAddress/MAC, purchaseDate/Kaufdatum, warrantyUntil/Garantie bis, cost/Kosten, notes/Notizen,
deviceHostname/Gerät. Dates as YYYY-MM-DD or DD.MM.YYYY.`,
		Example: `  opencm assets import inventar.csv --dry-run
  opencm assets import inventar.csv`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				DryRun   bool `json:"dryRun"`
				Rows     int  `json:"rows"`
				Created  int  `json:"created"`
				Updated  int  `json:"updated"`
				Skipped  int  `json:"skipped"`
				Errors   []struct {
					Line    int    `json:"line"`
					Message string `json:"message"`
				} `json:"errors"`
				Warnings []struct {
					Line    int    `json:"line"`
					Message string `json:"message"`
				} `json:"warnings"`
				UnknownColumns []string `json:"unknownColumns"`
			}
			if err := client.Do(http.MethodPost, "/assets/import", nil, map[string]any{"csv": string(data), "dryRun": dryRun}, &res); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[struct{}](cmd.OutOrStdout(), f, res, nil, nil)
			}
			w := cmd.OutOrStdout()
			mode := "imported"
			if res.DryRun {
				mode = "dry run (nothing changed)"
			}
			fmt.Fprintf(w, "%s: %d rows – %d new, %d updated, %d skipped\n", mode, res.Rows, res.Created, res.Updated, res.Skipped)
			for _, e := range res.Errors {
				fmt.Fprintf(w, "  error   line %d: %s\n", e.Line, e.Message)
			}
			for _, e := range res.Warnings {
				fmt.Fprintf(w, "  warning line %d: %s\n", e.Line, e.Message)
			}
			if len(res.UnknownColumns) > 0 {
				fmt.Fprintf(w, "  ignored columns: %s\n", strings.Join(res.UnknownColumns, ", "))
			}
			if len(res.Errors) > 0 {
				return &usageError{fmt.Sprintf("%d rows with errors", len(res.Errors))}
			}
			return nil
		},
	}
	imp.Flags().BoolVar(&dryRun, "dry-run", false, "only validate, change nothing")

	c.AddCommand(list, show, create, update, del, imp)
	return c
}
