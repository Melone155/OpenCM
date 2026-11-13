package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/output"
)

type device struct {
	ID              string  `json:"id"`
	Hostname        string  `json:"hostname"`
	OS              string  `json:"os"`
	OSVersion       string  `json:"osVersion"`
	Arch            string  `json:"arch"`
	AgentVersion    *string `json:"agentVersion"`
	Status          string  `json:"status"`
	Online          bool    `json:"online"`
	Manufacturer    *string `json:"manufacturer"`
	Model           *string `json:"model"`
	SerialNumber    *string `json:"serialNumber"`
	LoggedOnUser    *string `json:"loggedOnUser"`
	LastIP          *string `json:"lastIp"`
	LastSeenAt      *string `json:"lastSeenAt"`
	LastInventoryAt *string `json:"lastInventoryAt"`
	EnrolledAt      string  `json:"enrolledAt"`
	CertExpiresAt   *string `json:"certExpiresAt,omitempty"`
	Groups          []ref   `json:"groups,omitempty"`
}

func state(d device) string {
	switch {
	case d.Status == "revoked":
		return "revoked"
	case d.Online:
		return "online"
	}
	return "offline"
}

var deviceCols = []output.Column[device]{
	{Header: "ID", Value: func(d device) string { return d.ID }},
	{Header: "HOSTNAME", Value: func(d device) string { return d.Hostname }},
	{Header: "STATE", Value: state},
	{Header: "OS", Value: func(d device) string { return strings.TrimSpace(d.OS + " " + d.OSVersion) }},
	{Header: "USER", Value: func(d device) string { return deref(d.LoggedOnUser) }},
	{Header: "LAST SEEN", Value: func(d device) string { return deref(d.LastSeenAt) }},
}

// filterKeys maps --filter keys to API query parameters.
var filterKeys = map[string]string{"os": "os", "status": "status", "online": "online", "search": "search", "hostname": "search"}

// parseFilter turns "os=windows,online=true" into query values.
func parseFilter(expr string, q url.Values) error {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	for _, part := range strings.Split(expr, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		param, known := filterKeys[k]
		if !ok || !known || v == "" {
			return &usageError{fmt.Sprintf("invalid filter %q (allowed: os=, status=, online=, search=)", part)}
		}
		if k == "os" && v == "mac" {
			v = "macos"
		}
		q.Set(param, v)
	}
	return nil
}

func newDevicesCmd() *cobra.Command {
	c := &cobra.Command{Use: "devices", Aliases: []string{"device", "dev"}, Short: "Managed devices and their inventory"}

	var filter, search, sort string
	var limit, offset int
	var onlineOnly bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List devices",
		Example: `  opencm devices list --filter "os=windows"
  opencm devices list --filter "os=linux,online=false" -o json
  opencm devices list --search PC-01`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}, "sort": {sort}}
			if err := parseFilter(filter, q); err != nil {
				return err
			}
			if search != "" {
				q.Set("search", search)
			}
			if onlineOnly {
				q.Set("online", "true")
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var res struct {
				Items []device `json:"items"`
				Total int      `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/devices", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, deviceCols)
		},
	}
	list.Flags().StringVar(&filter, "filter", "", `filter, e.g. "os=windows,online=true" (keys: os, status, online, search)`)
	list.Flags().StringVar(&search, "search", "", "substring of hostname, serial number, user or model")
	list.Flags().BoolVar(&onlineOnly, "online", false, "only online devices")
	list.Flags().StringVar(&sort, "sort", "hostname", "hostname|lastSeenAt|enrolledAt")
	list.Flags().IntVar(&limit, "limit", 100, "page size (max 500)")
	list.Flags().IntVar(&offset, "offset", 0, "page offset")

	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Show device details",
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
			var d device
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0]), nil, nil, &d); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render(cmd.OutOrStdout(), f, d, []device{d}, deviceCols)
			}
			w := cmd.OutOrStdout()
			for _, kv := range [][2]string{
				{"ID", d.ID}, {"Hostname", d.Hostname}, {"State", state(d)}, {"OS", d.OS + " " + d.OSVersion}, {"Arch", d.Arch},
				{"Manufacturer", deref(d.Manufacturer)}, {"Model", deref(d.Model)}, {"Serial", deref(d.SerialNumber)},
				{"Logged on", deref(d.LoggedOnUser)}, {"Last IP", deref(d.LastIP)}, {"Last seen", deref(d.LastSeenAt)},
				{"Last inventory", deref(d.LastInventoryAt)}, {"Enrolled", d.EnrolledAt}, {"Agent", deref(d.AgentVersion)},
				{"Cert expires", deref(d.CertExpiresAt)}, {"Groups", names(d.Groups)},
			} {
				fmt.Fprintf(w, "%-16s %s\n", kv[0]+":", kv[1])
			}
			return nil
		},
	}

	var swSearch string
	software := &cobra.Command{
		Use:   "software <id>",
		Short: "List installed software of a device",
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
			q := url.Values{}
			if swSearch != "" {
				q.Set("search", swSearch)
			}
			type sw struct {
				Name        string  `json:"name"`
				Version     string  `json:"version"`
				Publisher   string  `json:"publisher"`
				InstallDate *string `json:"installDate"`
				Source      string  `json:"source"`
				Arch        string  `json:"arch"`
			}
			var res struct {
				Items []sw `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0])+"/software", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[sw]{
				{Header: "NAME", Value: func(s sw) string { return s.Name }},
				{Header: "VERSION", Value: func(s sw) string { return s.Version }},
				{Header: "PUBLISHER", Value: func(s sw) string { return s.Publisher }},
				{Header: "INSTALLED", Value: func(s sw) string { return deref(s.InstallDate) }},
				{Header: "SOURCE", Value: func(s sw) string { return s.Source }},
			})
		},
	}
	software.Flags().StringVar(&swSearch, "search", "", "filter by name or publisher")

	var category string
	var histLimit int
	history := &cobra.Command{
		Use:   "history <id>",
		Short: "Show the inventory change log of a device",
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
			q := url.Values{"limit": {strconv.Itoa(histLimit)}}
			if category != "" {
				q.Set("category", category)
			}
			type entry struct {
				At       string `json:"at"`
				Category string `json:"category"`
				Change   string `json:"change"`
				ItemKey  string `json:"itemKey"`
				OldValue any    `json:"oldValue"`
				NewValue any    `json:"newValue"`
			}
			var res struct {
				Items []entry `json:"items"`
				Total int     `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0])+"/history", q, nil, &res); err != nil {
				return err
			}
			show := func(v any) string {
				if v == nil {
					return "-"
				}
				return fmt.Sprint(v)
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[entry]{
				{Header: "TIME", Value: func(e entry) string { return e.At }},
				{Header: "CATEGORY", Value: func(e entry) string { return e.Category }},
				{Header: "CHANGE", Value: func(e entry) string { return e.Change }},
				{Header: "ITEM", Value: func(e entry) string { return e.ItemKey }},
				{Header: "OLD", Value: func(e entry) string { return show(e.OldValue) }},
				{Header: "NEW", Value: func(e entry) string { return show(e.NewValue) }},
			})
		},
	}
	history.Flags().StringVar(&category, "category", "", "software|hardware|os|patch|service|autostart|user|group|disk|device")
	history.Flags().IntVar(&histLimit, "limit", 100, "number of entries (max 500)")

	inventory := &cobra.Command{
		Use:   "inventory <id>",
		Short: "Print the full inventory snapshot (JSON/YAML)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			if f == output.Table {
				f = output.JSON // nested data: table makes no sense
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var inv map[string]any
			if err := client.Do(http.MethodGet, "/devices/"+url.PathEscape(args[0])+"/inventory", nil, nil, &inv); err != nil {
				return err
			}
			return output.Render[map[string]any](cmd.OutOrStdout(), f, inv, nil, nil)
		},
	}

	simple := func(use, short, method, suffix, done string) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <id>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, _, _, err := session()
				if err != nil {
					return err
				}
				if err := client.Do(method, "/devices/"+url.PathEscape(args[0])+suffix, nil, nil, nil); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), done+"\n", args[0])
				return nil
			},
		}
	}

	c.AddCommand(list, get, software, history, inventory,
		simple("request-inventory", "Ask the agent for a fresh inventory", http.MethodPost, "/inventory-request", "Inventory requested for %s"),
		simple("revoke", "Revoke the device certificate (immediate)", http.MethodPost, "/revoke", "Device %s revoked"),
		simple("delete", "Delete the device incl. inventory", http.MethodDelete, "", "Device %s deleted"),
	)
	return c
}

type enrollmentToken struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	MaxUses         *int    `json:"maxUses"`
	Uses            int     `json:"uses"`
	ExpiresAt       string  `json:"expiresAt"`
	RevokedAt       *string `json:"revokedAt"`
	CreatedAt       string  `json:"createdAt"`
	Token           string  `json:"token,omitempty"`
	InstallCommands *struct {
		Windows string `json:"windows"`
		Linux   string `json:"linux"`
		MacOS   string `json:"macos"`
	} `json:"installCommands,omitempty"`
}

func tokenState(t enrollmentToken) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.MaxUses != nil && t.Uses >= *t.MaxUses:
		return "used up"
	}
	if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil && exp.Before(time.Now()) {
		return "expired"
	}
	return "active"
}

func newEnrollmentCmd() *cobra.Command {
	c := &cobra.Command{Use: "enrollment-tokens", Aliases: []string{"tokens", "enroll"}, Short: "Enrollment tokens for new devices"}
	cols := []output.Column[enrollmentToken]{
		{Header: "ID", Value: func(t enrollmentToken) string { return t.ID }},
		{Header: "NAME", Value: func(t enrollmentToken) string { return t.Name }},
		{Header: "STATE", Value: tokenState},
		{Header: "USES", Value: func(t enrollmentToken) string {
			if t.MaxUses == nil {
				return strconv.Itoa(t.Uses)
			}
			return fmt.Sprintf("%d/%d", t.Uses, *t.MaxUses)
		}},
		{Header: "EXPIRES", Value: func(t enrollmentToken) string { return t.ExpiresAt }},
	}

	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List enrollment tokens",
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
				Items []enrollmentToken `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/enrollment-tokens", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, cols)
		},
	})

	var name, osName string
	var hours, maxUses int
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a token and print the install command",
		Example: `  opencm enrollment-tokens create --name "Rollout Buchhaltung" --max-uses 25 --os windows
  opencm enrollment-tokens create --name lab -o json | jq -r .installCommands.linux`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			if name == "" {
				return &usageError{"--name is required"}
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			body := map[string]any{"name": name, "expiresInHours": hours}
			if maxUses > 0 {
				body["maxUses"] = maxUses
			}
			var t enrollmentToken
			if err := client.Do(http.MethodPost, "/enrollment-tokens", nil, body, &t); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render(cmd.OutOrStdout(), f, t, []enrollmentToken{t}, cols)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Token (shown only once): %s\nExpires: %s\n\n", t.Token, t.ExpiresAt)
			if t.InstallCommands != nil {
				cmds := map[string]string{"windows": t.InstallCommands.Windows, "linux": t.InstallCommands.Linux, "macos": t.InstallCommands.MacOS}
				for _, o := range []string{"windows", "linux", "macos"} {
					if osName != "" && osName != o {
						continue
					}
					fmt.Fprintf(w, "# %s (run as Administrator/root)\n%s\n\n", o, cmds[o])
				}
			}
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "label for the token")
	create.Flags().IntVar(&hours, "expires-in", 168, "validity in hours (max 8760)")
	create.Flags().IntVar(&maxUses, "max-uses", 0, "maximum number of devices (0 = unlimited)")
	create.Flags().StringVar(&osName, "os", "", "only print the install command for windows|linux|macos")

	c.AddCommand(create, &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			if err := client.Do(http.MethodDelete, "/enrollment-tokens/"+url.PathEscape(args[0]), nil, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Token %s revoked\n", args[0])
			return nil
		},
	})
	return c
}

func newAgentCmd() *cobra.Command {
	c := &cobra.Command{Use: "agent", Short: "Agent binaries offered by the server"}
	c.AddCommand(&cobra.Command{
		Use:   "downloads",
		Short: "List available agent binaries with checksums",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			type bin struct {
				OS        string `json:"os"`
				Arch      string `json:"arch"`
				SizeBytes int64  `json:"sizeBytes"`
				SHA256    string `json:"sha256"`
				URL       string `json:"url"`
			}
			var res struct {
				Version *string `json:"version"`
				Items   []bin   `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/agent-downloads", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[bin]{
				{Header: "OS", Value: func(b bin) string { return b.OS }},
				{Header: "ARCH", Value: func(b bin) string { return b.Arch }},
				{Header: "SIZE", Value: func(b bin) string { return strconv.FormatInt(b.SizeBytes, 10) }},
				{Header: "SHA256", Value: func(b bin) string { return b.SHA256 }},
				{Header: "URL", Value: func(b bin) string { return client.Server + b.URL }},
			})
		},
	})

	var osName, arch, out string
	download := &cobra.Command{
		Use:     "download",
		Short:   "Download an agent binary",
		Example: `  opencm agent download --os windows --arch amd64 -f opencm-agent.exe`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if osName == "" || arch == "" || out == "" {
				return &usageError{"--os, --arch and --file are required"}
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			res, err := client.HTTP.Get(client.Server + "/api/v1/agent-downloads/" + url.PathEscape(osName) + "/" + url.PathEscape(arch))
			if err != nil {
				return err
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("download failed: HTTP %d", res.StatusCode)
			}
			f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, res.Body)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %s (%d bytes, sha256 %s)\n", out, n, res.Header.Get("x-checksum-sha256"))
			return nil
		},
	}
	download.Flags().StringVar(&osName, "os", "", "windows|linux|macos")
	download.Flags().StringVar(&arch, "arch", "amd64", "amd64|arm64")
	download.Flags().StringVarP(&out, "file", "f", "", "output file")
	c.AddCommand(download)
	return c
}
