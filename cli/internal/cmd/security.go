package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/output"
)

// ---------------------------------------------------------------- api tokens

type apiToken struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"`
	ExpiresAt   *string  `json:"expiresAt"`
	LastUsedAt  *string  `json:"lastUsedAt"`
	RevokedAt   *string  `json:"revokedAt"`
	CreatedAt   string   `json:"createdAt"`
	Token       string   `json:"token,omitempty"`
}

func newTokensCmd() *cobra.Command {
	c := &cobra.Command{Use: "tokens", Aliases: []string{"token"}, Short: "Personal API tokens (for scripts and CI)"}

	var all bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List your API tokens (--all: of all users, needs users:read)",
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
				Items []apiToken `json:"items"`
			}
			q := url.Values{}
			if all {
				q.Set("all", "true")
			}
			if err := client.Do(http.MethodGet, "/api-tokens", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[apiToken]{
				{Header: "ID", Value: func(t apiToken) string { return t.ID }},
				{Header: "NAME", Value: func(t apiToken) string { return t.Name }},
				{Header: "USER", Value: func(t apiToken) string { return t.Username }},
				{Header: "PERMISSIONS", Value: func(t apiToken) string {
					if len(t.Permissions) == 0 {
						return "(owner's rights)"
					}
					return strings.Join(t.Permissions, ",")
				}},
				{Header: "EXPIRES", Value: func(t apiToken) string { return deref(t.ExpiresAt) }},
				{Header: "LAST USED", Value: func(t apiToken) string { return deref(t.LastUsedAt) }},
				{Header: "REVOKED", Value: func(t apiToken) string { return deref(t.RevokedAt) }},
			})
		},
	}
	list.Flags().BoolVar(&all, "all", false, "tokens of all users")

	var perms []string
	var days int
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an API token; the secret is shown exactly once",
		Example: `  opencm tokens create ci-inventory --permission devices:read --permission inventory:read --days 30
  export OPENCM_TOKEN=$(opencm tokens create backup -o json | jq -r .token)`,
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
			if perms == nil {
				perms = []string{}
			}
			var t apiToken
			if err := client.Do(http.MethodPost, "/api-tokens", nil, map[string]any{"name": args[0], "permissions": perms, "expiresInDays": days}, &t); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[apiToken](cmd.OutOrStdout(), f, t, nil, nil)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", t.Token)
			fmt.Fprintf(os.Stderr, "Token %q (id %s) valid until %s – store it now, it cannot be shown again.\n", t.Name, t.ID, deref(t.ExpiresAt))
			return nil
		},
	}
	create.Flags().StringArrayVar(&perms, "permission", nil, "limit the token to this permission (repeatable; default: your own rights)")
	create.Flags().IntVar(&days, "days", 90, "lifetime in days")

	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			if err := client.Do(http.MethodDelete, "/api-tokens/"+url.PathEscape(args[0]), nil, nil, nil); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Token revoked")
			return nil
		},
	}
	c.AddCommand(list, create, revoke)
	return c
}

// ---------------------------------------------------------------- audit export

func newAuditExportCmd() *cobra.Command {
	var exportFormat, file, action, since, until string
	c := &cobra.Command{
		Use:   "export",
		Short: "Export the audit log as CSV (Excel-compatible) or JSON",
		Example: `  opencm audit export --format csv -f audit-2026-11.csv --since 2026-11-01T00:00:00Z
  opencm audit export --format json --action auth.login_failed > failed.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if exportFormat != "csv" && exportFormat != "json" {
				return &usageError{"--format must be csv or json"}
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"format": {exportFormat}}
			for k, v := range map[string]string{"action": action, "from": since, "to": until} {
				if v != "" {
					q.Set(k, v)
				}
			}
			body, err := client.Raw(http.MethodGet, "/audit-log/export", q)
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
			n, err := io.Copy(w, body)
			if err != nil {
				return err
			}
			if file != "" && file != "-" {
				fmt.Fprintf(os.Stderr, "%d bytes written to %s\n", n, file)
			}
			return nil
		},
	}
	c.Flags().StringVar(&exportFormat, "format", "csv", "csv|json")
	c.Flags().StringVarP(&file, "file", "f", "", "output file (default: stdout)")
	c.Flags().StringVar(&action, "action", "", "filter by action")
	c.Flags().StringVar(&since, "since", "", "from this RFC3339 timestamp")
	c.Flags().StringVar(&until, "until", "", "up to this RFC3339 timestamp")
	return c
}
