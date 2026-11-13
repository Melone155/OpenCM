package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/opencm/opencm/cli/internal/api"
	"github.com/opencm/opencm/cli/internal/config"
	"github.com/opencm/opencm/cli/internal/output"
)

type me struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Email       *string  `json:"email"`
	Permissions []string `json:"permissions"`
}

func newLoginCmd() *cobra.Command {
	var server, username, profile, otp string
	var passwordStdin, insecure bool
	c := &cobra.Command{
		Use:   "login",
		Short: "Log in to an OpenCM server and store the session in a profile",
		Example: `  opencm login --server https://cm.example.org --username admin
  echo "$PW" | opencm login --server https://cm.example.org -u admin --password-stdin --name prod`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if profile == "" {
				profile = g.profile
			}
			if profile == "" {
				profile = cfg.Current
			}
			if profile == "" {
				profile = "default"
			}
			existing := cfg.Profiles[profile]
			if server == "" && existing != nil {
				server = existing.Server
			}
			if server == "" {
				return &usageError{"--server is required for a new profile"}
			}
			if username == "" && existing != nil {
				username = existing.Username
			}
			in := bufio.NewReader(os.Stdin)
			if username == "" {
				fmt.Fprint(os.Stderr, "Username: ")
				line, _ := in.ReadString('\n')
				username = strings.TrimSpace(line)
			}
			password, err := readPassword(in, passwordStdin)
			if err != nil {
				return err
			}

			client := api.New(server, "", insecure)
			var res struct {
				Token            string `json:"token"`
				ExpiresAt        string `json:"expiresAt"`
				MfaSetupRequired bool   `json:"mfaSetupRequired"`
				User             me     `json:"user"`
			}
			body := map[string]string{"username": username, "password": password}
			if otp != "" {
				body["otp"] = otp
			}
			err = client.Do(http.MethodPost, "/auth/login", nil, body, &res)
			var apiErr *api.Error
			if errors.As(err, &apiErr) && apiErr.Code == "mfa_required" && otp == "" {
				// second factor: prompt when interactive, otherwise --otp is required
				if passwordStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
					return &usageError{"two-factor authentication is enabled – pass --otp <code>"}
				}
				fmt.Fprint(os.Stderr, "Authenticator code (or recovery code): ")
				line, _ := in.ReadString('\n')
				body["otp"] = strings.TrimSpace(line)
				err = client.Do(http.MethodPost, "/auth/login", nil, body, &res)
			}
			if err != nil {
				return err
			}
			if res.MfaSetupRequired {
				fmt.Fprintln(os.Stderr, "Warning: two-factor authentication is mandatory on this server – set it up in the web UI (Profile) before using the CLI.")
			}
			cfg.Profiles[profile] = &config.Profile{Server: client.Server, Token: res.Token, Username: username, Insecure: insecure}
			cfg.Current = profile
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Logged in as %s on %s (profile %q, session valid until %s)\n", res.User.Username, client.Server, profile, res.ExpiresAt)
			return nil
		},
	}
	c.Flags().StringVarP(&server, "server", "s", "", "server URL, e.g. https://cm.example.org")
	c.Flags().StringVarP(&username, "username", "u", "", "username")
	c.Flags().StringVar(&profile, "name", "", "profile name to create/update (default: current or \"default\")")
	c.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	c.Flags().StringVar(&otp, "otp", "", "two-factor code (TOTP or recovery code); prompted interactively if needed")
	c.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification (lab use only)")
	return c
}

func stdinReader() *bufio.Reader { return bufio.NewReader(os.Stdin) }

func readPassword(in *bufio.Reader, fromStdin bool) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(in)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", &usageError{"no terminal for password prompt – use --password-stdin"}
	}
	fmt.Fprint(os.Stderr, "Password: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "End the session and remove the token from the profile",
		RunE: func(*cobra.Command, []string) error {
			client, cfg, name, err := session()
			if err != nil {
				return err
			}
			// Ignore server errors (e.g. already expired) – the local token is removed anyway.
			_ = client.Do(http.MethodPost, "/auth/logout", nil, nil, nil)
			cfg.Profiles[name].Token = ""
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Logged out (profile %q)\n", name)
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current user and effective permissions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := format()
			if err != nil {
				return err
			}
			client, _, _, err := session()
			if err != nil {
				return err
			}
			var m me
			if err := client.Do(http.MethodGet, "/auth/me", nil, nil, &m); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, m, []me{m}, []output.Column[me]{
				{Header: "USERNAME", Value: func(m me) string { return m.Username }},
				{Header: "NAME", Value: func(m me) string { return m.DisplayName }},
				{Header: "PERMISSIONS", Value: func(m me) string { return strings.Join(m.Permissions, ",") }},
			})
		},
	}
}

func newProfileCmd() *cobra.Command {
	c := &cobra.Command{Use: "profile", Short: "Manage server profiles"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			for _, n := range cfg.Names() {
				mark := " "
				if n == cfg.Current {
					mark = "*"
				}
				p := cfg.Profiles[n]
				state := "logged out"
				if p.Token != "" {
					state = "logged in as " + p.Username
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %-15s %-40s %s\n", mark, n, p.Server, state)
			}
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "use <name>",
		Short: "Switch the current profile",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			cfg, _ := config.Load()
			if cfg == nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return cfg.Names(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, ok := cfg.Profiles[args[0]]; !ok {
				return &usageError{fmt.Sprintf("unknown profile %q", args[0])}
			}
			cfg.Current = args[0]
			return cfg.Save()
		},
	})
	return c
}
