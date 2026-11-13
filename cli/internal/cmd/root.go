// Package cmd implements the opencm command tree.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/api"
	"github.com/opencm/opencm/cli/internal/config"
	"github.com/opencm/opencm/cli/internal/output"
)

// Version is set at build time: -ldflags "-X github.com/opencm/opencm/cli/internal/cmd.Version=..."
var Version = "dev"

// Exit codes (documented in docs/cli.md).
const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitUnauthorized = 3
	ExitForbidden    = 4
	ExitNotFound     = 5
	ExitConflict     = 6
)

type globals struct {
	profile string
	output  string
}

var g globals

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "opencm",
		Short:         "OpenCM command-line client",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&g.profile, "profile", "p", os.Getenv("OPENCM_PROFILE"), "server profile (default: current profile)")
	root.PersistentFlags().StringVarP(&g.output, "output", "o", "table", "output format: table|json|yaml")
	_ = root.RegisterFlagCompletionFunc("output", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp
	})

	root.AddCommand(newLoginCmd(), newLogoutCmd(), newWhoamiCmd(), newProfileCmd(), newUsersCmd(), newRolesCmd(), newAuditCmd(),
		newDevicesCmd(), newEnrollmentCmd(), newAgentCmd(), newGroupsCmd(), newScriptsCmd(), newJobsCmd(), newTasksCmd(), newCveCmd(), newSoftwareCmd(), newTokensCmd(), newApprovalsCmd(),
		newPackagesCmd(), newDeployCmd(), newDeploymentsCmd(), newPatchesCmd(),
		newDashboardCmd(), newReportsCmd(), newWebhooksCmd(), newLicensesCmd(),
		newSecurityCmd(), newAssetsCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	err := newRoot().Execute()
	if err == nil {
		return ExitOK
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case 400:
			return ExitUsage
		case 401:
			return ExitUnauthorized
		case 403:
			return ExitForbidden
		case 404:
			return ExitNotFound
		case 409:
			return ExitConflict
		}
	}
	var usage *usageError
	if errors.As(err, &usage) {
		return ExitUsage
	}
	var failed *runFailedError
	if errors.As(err, &failed) {
		return ExitRunFailed
	}
	var pending *pendingApprovalError
	if errors.As(err, &pending) {
		return ExitPendingApproval
	}
	return ExitError
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// session loads the selected profile and returns an authenticated client.
func session() (*api.Client, *config.Config, string, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, "", err
	}
	name, p, err := cfg.Resolve(g.profile)
	if err != nil {
		return nil, nil, "", err
	}
	token := p.Token
	if env := os.Getenv("OPENCM_TOKEN"); env != "" {
		token = env
	}
	if token == "" {
		return nil, nil, "", &api.Error{Status: 401, Message: fmt.Sprintf("not logged in (profile %q) – run `opencm login`", name)}
	}
	return api.New(p.Server, token, p.Insecure), cfg, name, nil
}

func format() (output.Format, error) {
	f, err := output.Parse(g.output)
	if err != nil {
		return "", &usageError{err.Error()}
	}
	return f, nil
}
