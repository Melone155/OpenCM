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

type ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type user struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"displayName"`
	Email       *string `json:"email"`
	AuthSource  string  `json:"authSource"`
	IsActive    bool    `json:"isActive"`
	LastLoginAt *string `json:"lastLoginAt"`
	Roles       []ref   `json:"roles,omitempty"`
	Groups      []ref   `json:"groups,omitempty"`
}

var userCols = []output.Column[user]{
	{Header: "ID", Value: func(u user) string { return u.ID }},
	{Header: "USERNAME", Value: func(u user) string { return u.Username }},
	{Header: "NAME", Value: func(u user) string { return u.DisplayName }},
	{Header: "SOURCE", Value: func(u user) string { return u.AuthSource }},
	{Header: "ACTIVE", Value: func(u user) string { return strconv.FormatBool(u.IsActive) }},
	{Header: "LAST LOGIN", Value: func(u user) string { return deref(u.LastLoginAt) }},
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func names(refs []ref) string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Name
	}
	return strings.Join(out, ",")
}

func newUsersCmd() *cobra.Command {
	c := &cobra.Command{Use: "users", Aliases: []string{"user"}, Short: "Manage users"}

	var search string
	var limit, offset int
	list := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}
			if search != "" {
				q.Set("search", search)
			}
			var res struct {
				Items []user `json:"items"`
				Total int    `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/users", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, userCols)
		},
	}
	list.Flags().StringVar(&search, "search", "", "filter by username/display name")
	list.Flags().IntVar(&limit, "limit", 100, "page size (max 500)")
	list.Flags().IntVar(&offset, "offset", 0, "page offset")

	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a user incl. roles and groups",
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
			var u user
			if err := client.Do(http.MethodGet, "/users/"+url.PathEscape(args[0]), nil, nil, &u); err != nil {
				return err
			}
			cols := append(append([]output.Column[user]{}, userCols...),
				output.Column[user]{Header: "ROLES", Value: func(u user) string { return names(u.Roles) }},
				output.Column[user]{Header: "GROUPS", Value: func(u user) string { return names(u.Groups) }})
			return output.Render(cmd.OutOrStdout(), f, u, []user{u}, cols)
		},
	}

	var cu struct {
		username, displayName, email string
		roleIDs                      []string
		passwordStdin                bool
	}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a local user",
		Example: `  opencm users create --username max --display-name "Max Muster" --role <role-id>
  echo "$PW" | opencm users create --username svc-backup --password-stdin`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			if cu.username == "" {
				return &usageError{"--username is required"}
			}
			pw, err := readPassword(stdinReader(), cu.passwordStdin)
			if err != nil {
				return err
			}
			body := map[string]any{"username": cu.username, "displayName": cu.displayName, "password": pw, "roleIds": cu.roleIDs}
			if cu.email != "" {
				body["email"] = cu.email
			}
			var u user
			if err := client.Do(http.MethodPost, "/users", nil, body, &u); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, u, []user{u}, userCols)
		},
	}
	create.Flags().StringVar(&cu.username, "username", "", "username")
	create.Flags().StringVar(&cu.displayName, "display-name", "", "display name")
	create.Flags().StringVar(&cu.email, "email", "", "e-mail address")
	create.Flags().StringSliceVar(&cu.roleIDs, "role", nil, "role id (repeatable)")
	create.Flags().BoolVar(&cu.passwordStdin, "password-stdin", false, "read the password from stdin")

	setActive := func(use, short string, active bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <id>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, _, _, err := session()
				if err != nil {
					return err
				}
				if err := client.Do(http.MethodPatch, "/users/"+url.PathEscape(args[0]), nil, map[string]bool{"isActive": active}, nil); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "User %s %sd\n", args[0], use)
				return nil
			},
		}
	}

	del := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			if err := client.Do(http.MethodDelete, "/users/"+url.PathEscape(args[0]), nil, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "User %s deleted\n", args[0])
			return nil
		},
	}

	c.AddCommand(list, get, create, setActive("activate", "Activate a user", true), setActive("deactivate", "Deactivate a user (ends all sessions)", false), del)
	return c
}

type role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"isSystem"`
}

func newRolesCmd() *cobra.Command {
	c := &cobra.Command{Use: "roles", Aliases: []string{"role"}, Short: "Manage roles"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List roles",
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
				Items []role `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/roles", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[role]{
				{Header: "ID", Value: func(r role) string { return r.ID }},
				{Header: "NAME", Value: func(r role) string { return r.Name }},
				{Header: "SYSTEM", Value: func(r role) string { return strconv.FormatBool(r.IsSystem) }},
				{Header: "PERMISSIONS", Value: func(r role) string { return strings.Join(r.Permissions, ",") }},
			})
		},
	})
	return c
}

type auditEntry struct {
	ID         int            `json:"id"`
	At         string         `json:"at"`
	ActorType  string         `json:"actorType"`
	ActorName  string         `json:"actorName"`
	Action     string         `json:"action"`
	TargetType *string        `json:"targetType"`
	TargetID   *string        `json:"targetId"`
	Details    map[string]any `json:"details"`
	IP         *string        `json:"ip"`
}

func newAuditCmd() *cobra.Command {
	var action, actorID, since string
	var limit, offset int
	c := &cobra.Command{Use: "audit", Short: "Query the audit log"}
	list := &cobra.Command{
		Use:     "list",
		Short:   "List audit entries (newest first)",
		Example: `  opencm audit list --action user.create --since 2026-11-01T00:00:00Z -o json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}}
			for k, v := range map[string]string{"action": action, "actorId": actorID, "from": since} {
				if v != "" {
					q.Set(k, v)
				}
			}
			var res struct {
				Items []auditEntry `json:"items"`
				Total int          `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/audit-log", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[auditEntry]{
				{Header: "TIME", Value: func(e auditEntry) string { return e.At }},
				{Header: "ACTOR", Value: func(e auditEntry) string { return e.ActorName }},
				{Header: "ACTION", Value: func(e auditEntry) string { return e.Action }},
				{Header: "TARGET", Value: func(e auditEntry) string { return deref(e.TargetType) + " " + deref(e.TargetID) }},
				{Header: "IP", Value: func(e auditEntry) string { return deref(e.IP) }},
			})
		},
	}
	list.Flags().StringVar(&action, "action", "", "filter by action, e.g. auth.login_failed")
	list.Flags().StringVar(&actorID, "actor", "", "filter by actor user id")
	list.Flags().StringVar(&since, "since", "", "only entries at/after this RFC3339 timestamp")
	list.Flags().IntVar(&limit, "limit", 50, "page size (max 500)")
	list.Flags().IntVar(&offset, "offset", 0, "page offset")
	c.AddCommand(list, newAuditExportCmd())
	return c
}
