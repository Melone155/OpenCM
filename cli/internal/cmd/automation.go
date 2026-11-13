package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/opencm/opencm/cli/internal/api"
	"github.com/opencm/opencm/cli/internal/output"
)

// ExitRunFailed is returned by --watch when at least one device failed.
const ExitRunFailed = 7

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type runFailedError struct{ msg string }

func (e *runFailedError) Error() string { return e.msg }

// ---------------------------------------------------------------- types

type scriptParam struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
}

type scriptVersion struct {
	ID         string        `json:"id"`
	Version    int           `json:"version"`
	Status     string        `json:"status"`
	SHA256     string        `json:"sha256"`
	ChangeNote string        `json:"changeNote"`
	Parameters []scriptParam `json:"parameters"`
	CreatedAt  string        `json:"createdAt"`
	Content    string        `json:"content,omitempty"`
}

type script struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Interpreter     string          `json:"interpreter"`
	LatestVersion   int             `json:"latestVersion"`
	ApprovedVersion *int            `json:"approvedVersion"`
	UpdatedAt       string          `json:"updatedAt"`
	Versions        []scriptVersion `json:"versions,omitempty"`
}

type jobTargets struct {
	DeviceIDs  []string `json:"deviceIds"`
	GroupIDs   []string `json:"groupIds"`
	AllDevices bool     `json:"allDevices"`
}

type job struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Enabled   bool       `json:"enabled"`
	Trigger   string     `json:"trigger"`
	Cron      *string    `json:"cron"`
	Timezone  string     `json:"timezone"`
	NextRunAt *string    `json:"nextRunAt"`
	LastRunAt *string    `json:"lastRunAt"`
	Targets   jobTargets `json:"targets"`
	StepCount int        `json:"stepCount,omitempty"`
	Steps     []struct {
		Position   int    `json:"position"`
		ScriptName string `json:"scriptName"`
		Version    int    `json:"version"`
	} `json:"steps,omitempty"`
}

type run struct {
	ID         string         `json:"id"`
	JobID      *string        `json:"jobId"`
	Name       string         `json:"name"`
	Trigger    string         `json:"trigger"`
	Status     string         `json:"status"`
	CreatedAt  string         `json:"createdAt"`
	FinishedAt *string        `json:"finishedAt"`
	Counts     map[string]int `json:"counts"`
}

type task struct {
	ID       string  `json:"id"`
	Hostname string  `json:"hostname"`
	Status   string  `json:"status"`
	Attempt  int     `json:"attempt"`
	ExitCode *int    `json:"exitCode"`
	Error    *string `json:"error"`
}

func countsText(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		if k != "total" && c[k] > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, c[k])
	}
	return fmt.Sprintf("%d devices: %s", c["total"], strings.Join(parts, " "))
}

var runCols = []output.Column[run]{
	{Header: "ID", Value: func(r run) string { return r.ID }},
	{Header: "NAME", Value: func(r run) string { return r.Name }},
	{Header: "TRIGGER", Value: func(r run) string { return r.Trigger }},
	{Header: "STATUS", Value: func(r run) string { return r.Status }},
	{Header: "TASKS", Value: func(r run) string { return countsText(r.Counts) }},
	{Header: "STARTED", Value: func(r run) string { return r.CreatedAt }},
}

// ---------------------------------------------------------------- helpers

// parseTargets resolves --target values: all | group:<name|id> | device:<hostname|id> | <hostname|id>.
func parseTargets(c *api.Client, specs []string) (jobTargets, error) {
	t := jobTargets{DeviceIDs: []string{}, GroupIDs: []string{}}
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	for _, spec := range specs {
		kind, val, ok := strings.Cut(spec, ":")
		if !ok {
			kind, val = "device", spec
		}
		switch strings.ToLower(kind) {
		case "all":
			t.AllDevices = true
		case "group", "g":
			if groups == nil {
				var res struct {
					Items []struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"items"`
				}
				if err := c.Do(http.MethodGet, "/device-groups", nil, nil, &res); err != nil {
					return t, err
				}
				groups = res.Items
			}
			found := ""
			for _, g := range groups {
				if g.ID == val || strings.EqualFold(g.Name, val) {
					found = g.ID
				}
			}
			if found == "" {
				return t, &usageError{fmt.Sprintf("unknown device group %q", val)}
			}
			t.GroupIDs = append(t.GroupIDs, found)
		case "device", "d":
			if uuidRe.MatchString(val) {
				t.DeviceIDs = append(t.DeviceIDs, val)
				continue
			}
			var res struct {
				Items []device `json:"items"`
			}
			if err := c.Do(http.MethodGet, "/devices", url.Values{"search": {val}, "limit": {"500"}}, nil, &res); err != nil {
				return t, err
			}
			found := ""
			for _, d := range res.Items {
				if strings.EqualFold(d.Hostname, val) {
					found = d.ID
				}
			}
			if found == "" {
				return t, &usageError{fmt.Sprintf("no device with hostname %q", val)}
			}
			t.DeviceIDs = append(t.DeviceIDs, found)
		default:
			return t, &usageError{fmt.Sprintf("invalid target %q (all | group:<name> | device:<hostname>)", spec)}
		}
	}
	if !t.AllDevices && len(t.DeviceIDs) == 0 && len(t.GroupIDs) == 0 {
		return t, &usageError{"at least one --target is required"}
	}
	return t, nil
}

// parseParams converts --param k=v using the script's parameter definitions.
func parseParams(defs []scriptParam, kvs []string) (map[string]any, error) {
	out := map[string]any{}
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, &usageError{fmt.Sprintf("invalid --param %q (expected name=value)", kv)}
		}
		var def *scriptParam
		for i := range defs {
			if strings.EqualFold(defs[i].Name, k) {
				def = &defs[i]
			}
		}
		if def == nil {
			return nil, &usageError{fmt.Sprintf("unknown parameter %q", k)}
		}
		switch def.Type {
		case "number":
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, &usageError{fmt.Sprintf("parameter %q must be a number", k)}
			}
			out[def.Name] = n
		case "boolean":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, &usageError{fmt.Sprintf("parameter %q must be true/false", k)}
			}
			out[def.Name] = b
		default:
			out[def.Name] = v
		}
	}
	return out, nil
}

// watchRun polls a run until it is finished and returns ExitRunFailed-style errors.
func watchRun(cmd *cobra.Command, c *api.Client, f output.Format, runID string) error {
	w := cmd.ErrOrStderr()
	last := ""
	var r run
	for {
		if err := c.Do(http.MethodGet, "/runs/"+url.PathEscape(runID), nil, nil, &r); err != nil {
			return err
		}
		line := fmt.Sprintf("%s  %s", r.Status, countsText(r.Counts))
		if line != last && f == output.Table {
			fmt.Fprintf(w, "[%s] %s\n", time.Now().Format("15:04:05"), line)
			last = line
		}
		if r.FinishedAt != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	var ts struct {
		Items []task `json:"items"`
	}
	if err := c.Do(http.MethodGet, "/runs/"+url.PathEscape(runID)+"/tasks", nil, nil, &ts); err != nil {
		return err
	}
	if err := output.Render(cmd.OutOrStdout(), f, map[string]any{"run": r, "tasks": ts.Items}, ts.Items, []output.Column[task]{
		{Header: "TASK", Value: func(t task) string { return t.ID }},
		{Header: "DEVICE", Value: func(t task) string { return t.Hostname }},
		{Header: "STATUS", Value: func(t task) string { return t.Status }},
		{Header: "EXIT", Value: func(t task) string {
			if t.ExitCode == nil {
				return "-"
			}
			return strconv.Itoa(*t.ExitCode)
		}},
		{Header: "ATTEMPT", Value: func(t task) string { return strconv.Itoa(t.Attempt) }},
		{Header: "ERROR", Value: func(t task) string { return deref(t.Error) }},
	}); err != nil {
		return err
	}
	if r.Counts["failed"]+r.Counts["timeout"] > 0 {
		return &runFailedError{fmt.Sprintf("run %s: %d device(s) failed", runID, r.Counts["failed"]+r.Counts["timeout"])}
	}
	return nil
}

func startedRun(cmd *cobra.Command, c *api.Client, f output.Format, r run, watch bool) error {
	if watch {
		if f == output.Table {
			fmt.Fprintf(cmd.ErrOrStderr(), "Run %s started (%s)\n", r.ID, countsText(r.Counts))
		}
		return watchRun(cmd, c, f, r.ID)
	}
	return output.Render(cmd.OutOrStdout(), f, r, []run{r}, runCols)
}

// ---------------------------------------------------------------- scripts

func newScriptsCmd() *cobra.Command {
	c := &cobra.Command{Use: "scripts", Aliases: []string{"script"}, Short: "Script library"}

	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List scripts",
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
				Items []script `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/scripts", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[script]{
				{Header: "ID", Value: func(s script) string { return s.ID }},
				{Header: "NAME", Value: func(s script) string { return s.Name }},
				{Header: "INTERPRETER", Value: func(s script) string { return s.Interpreter }},
				{Header: "LATEST", Value: func(s script) string { return "v" + strconv.Itoa(s.LatestVersion) }},
				{Header: "APPROVED", Value: func(s script) string {
					if s.ApprovedVersion == nil {
						return "-"
					}
					return "v" + strconv.Itoa(*s.ApprovedVersion)
				}},
			})
		},
	})

	var showVersion int
	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a script and its versions (--version N prints the content)",
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
			if showVersion > 0 {
				var v scriptVersion
				if err := client.Do(http.MethodGet, fmt.Sprintf("/scripts/%s/versions/%d", url.PathEscape(args[0]), showVersion), nil, nil, &v); err != nil {
					return err
				}
				if f == output.Table {
					_, err := io.WriteString(cmd.OutOrStdout(), v.Content)
					return err
				}
				return output.Render[scriptVersion](cmd.OutOrStdout(), f, v, nil, nil)
			}
			var s script
			if err := client.Do(http.MethodGet, "/scripts/"+url.PathEscape(args[0]), nil, nil, &s); err != nil {
				return err
			}
			if f != output.Table {
				return output.Render[script](cmd.OutOrStdout(), f, s, nil, nil)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n%s\n\n", s.Name, s.Interpreter, s.Description)
			return output.Render(cmd.OutOrStdout(), f, s, s.Versions, []output.Column[scriptVersion]{
				{Header: "VERSION", Value: func(v scriptVersion) string { return "v" + strconv.Itoa(v.Version) }},
				{Header: "STATUS", Value: func(v scriptVersion) string { return v.Status }},
				{Header: "CREATED", Value: func(v scriptVersion) string { return v.CreatedAt }},
				{Header: "NOTE", Value: func(v scriptVersion) string { return v.ChangeNote }},
			})
		},
	}
	get.Flags().IntVar(&showVersion, "version", 0, "print the content of this version")

	var targets, params []string
	var version, timeout int
	var watch bool
	runCmd := &cobra.Command{
		Use:   "run <id>",
		Short: "Run an approved script now on devices or groups",
		Example: `  opencm scripts run <id> --target group:Buchhaltung
  opencm scripts run <id> --target device:PC-0815 --param Days=7 --watch
  opencm scripts run <id> --target all -o json`,
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
			t, err := parseTargets(client, targets)
			if err != nil {
				return err
			}
			// parameter definitions of the version that will run
			var s script
			if err := client.Do(http.MethodGet, "/scripts/"+url.PathEscape(args[0]), nil, nil, &s); err != nil {
				return err
			}
			v := version
			if v == 0 {
				if s.ApprovedVersion == nil {
					return &usageError{fmt.Sprintf("script %q has no approved version", s.Name)}
				}
				v = *s.ApprovedVersion
			}
			var defs []scriptParam
			for _, sv := range s.Versions {
				if sv.Version == v {
					defs = sv.Parameters
				}
			}
			p, err := parseParams(defs, params)
			if err != nil {
				return err
			}
			body := map[string]any{"targets": t, "params": p, "version": v, "timeoutSeconds": timeout}
			var r runStart
			if err := client.Do(http.MethodPost, "/scripts/"+url.PathEscape(args[0])+"/run", nil, body, &r); err != nil {
				return err
			}
			return handleRunStart(cmd, client, f, r, watch)
		},
	}
	runCmd.Flags().StringArrayVarP(&targets, "target", "t", nil, "all | group:<name> | device:<hostname> (repeatable)")
	runCmd.Flags().StringArrayVar(&params, "param", nil, "parameter name=value (repeatable)")
	runCmd.Flags().IntVar(&version, "version", 0, "approved version (default: newest approved)")
	runCmd.Flags().IntVar(&timeout, "timeout", 3600, "timeout in seconds")
	runCmd.Flags().BoolVarP(&watch, "watch", "w", false, "wait for the result (exit code 7 if a device failed)")

	c.AddCommand(get, runCmd)
	return c
}

// ---------------------------------------------------------------- jobs / runs / tasks

func newJobsCmd() *cobra.Command {
	c := &cobra.Command{Use: "jobs", Aliases: []string{"job"}, Short: "Jobs and their runs"}

	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List jobs",
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
				Items []job `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/jobs", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[job]{
				{Header: "ID", Value: func(j job) string { return j.ID }},
				{Header: "NAME", Value: func(j job) string { return j.Name }},
				{Header: "TRIGGER", Value: func(j job) string {
					if j.Cron != nil {
						return j.Trigger + " " + *j.Cron
					}
					return j.Trigger
				}},
				{Header: "ENABLED", Value: func(j job) string { return strconv.FormatBool(j.Enabled) }},
				{Header: "NEXT RUN", Value: func(j job) string { return deref(j.NextRunAt) }},
				{Header: "LAST RUN", Value: func(j job) string { return deref(j.LastRunAt) }},
			})
		},
	})

	var deviceIDs []string
	var watch bool
	runJob := &cobra.Command{
		Use:   "run <job-id>",
		Short: "Start a job now",
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
			body := map[string]any{}
			if len(deviceIDs) > 0 {
				body["deviceIds"] = deviceIDs
			}
			var r runStart
			if err := client.Do(http.MethodPost, "/jobs/"+url.PathEscape(args[0])+"/run", nil, body, &r); err != nil {
				return err
			}
			return handleRunStart(cmd, client, f, r, watch)
		},
	}
	runJob.Flags().StringSliceVar(&deviceIDs, "device", nil, "restrict to these target device ids")
	runJob.Flags().BoolVarP(&watch, "watch", "w", false, "wait for the result")

	var statusWatch bool
	status := &cobra.Command{
		Use:   "status <run-id|job-id>",
		Short: "Show a run (or the latest run of a job), optionally until it finishes",
		Example: `  opencm jobs status <run-id> --watch
  opencm jobs status <job-id> -o json`,
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
			runID := args[0]
			var r run
			err = client.Do(http.MethodGet, "/runs/"+url.PathEscape(runID), nil, nil, &r)
			var apiErr *api.Error
			if errors.As(err, &apiErr) && apiErr.Status == 404 {
				var res struct {
					Items []run `json:"items"`
				}
				if err := client.Do(http.MethodGet, "/jobs/"+url.PathEscape(args[0])+"/runs", url.Values{"limit": {"1"}}, nil, &res); err != nil {
					return err
				}
				if len(res.Items) == 0 {
					return &api.Error{Status: 404, Message: "job has not run yet"}
				}
				r, runID = res.Items[0], res.Items[0].ID
			} else if err != nil {
				return err
			}
			if statusWatch || r.FinishedAt != nil {
				return watchRun(cmd, client, f, runID)
			}
			return output.Render(cmd.OutOrStdout(), f, r, []run{r}, runCols)
		},
	}
	status.Flags().BoolVarP(&statusWatch, "watch", "w", false, "wait until the run is finished")

	simple := func(use, short, path, done string, body func() any) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <run-id>",
			Short: short,
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
				// a mass rerun answers 202 with an approval request instead of a run (four-eyes)
				var rs runStart
				if err := client.Do(http.MethodPost, "/runs/"+url.PathEscape(args[0])+path, nil, body(), &rs); err != nil {
					return err
				}
				if rs.ApprovalRequired {
					return handleRunStart(cmd, client, f, rs, false)
				}
				r := rs.run
				if f == output.Table {
					fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", done, r.ID)
				}
				return output.Render(cmd.OutOrStdout(), f, r, []run{r}, runCols)
			},
		}
	}
	var all bool
	rerun := simple("rerun", "Run again for failed devices (--all: every device)", "/rerun", "New run", func() any { return map[string]bool{"onlyFailed": !all} })
	rerun.Flags().BoolVar(&all, "all", false, "rerun on all devices, not only failed ones")

	c.AddCommand(runJob, status, simple("cancel", "Cancel a run", "/cancel", "Cancelled", func() any { return map[string]any{} }), rerun, newRunsListCmd())
	return c
}

func newRunsListCmd() *cobra.Command {
	var limit int
	var jobID string
	c := &cobra.Command{
		Use:   "runs",
		Short: "List recent runs (incl. ad-hoc and test runs)",
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
			if jobID != "" {
				q.Set("jobId", jobID)
			}
			var res struct {
				Items []run `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/runs", q, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, runCols)
		},
	}
	c.Flags().IntVar(&limit, "limit", 20, "number of runs")
	c.Flags().StringVar(&jobID, "job", "", "only runs of this job")
	return c
}

func newTasksCmd() *cobra.Command {
	c := &cobra.Command{Use: "tasks", Aliases: []string{"task"}, Short: "Per-device task output"}
	var follow bool
	out := &cobra.Command{
		Use:   "output <task-id>",
		Short: "Print the output of a task (--follow streams until it finishes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, _, err := session()
			if err != nil {
				return err
			}
			cursor := 0
			for {
				var res struct {
					Items []struct {
						ID     int    `json:"id"`
						Stream string `json:"stream"`
						Data   string `json:"data"`
					} `json:"items"`
					NextCursor int    `json:"nextCursor"`
					Status     string `json:"status"`
					Done       bool   `json:"done"`
				}
				q := url.Values{"after": {strconv.Itoa(cursor)}, "limit": {"2000"}}
				if err := client.Do(http.MethodGet, "/tasks/"+url.PathEscape(args[0])+"/output", q, nil, &res); err != nil {
					return err
				}
				for _, it := range res.Items {
					w := cmd.OutOrStdout()
					if it.Stream != "stdout" {
						w = os.Stderr
					}
					_, _ = io.WriteString(w, it.Data)
				}
				cursor = res.NextCursor
				if res.Done || (!follow && len(res.Items) < 2000) {
					if res.Done {
						fmt.Fprintf(cmd.ErrOrStderr(), "\n[task %s]\n", res.Status)
						if res.Status == "failed" || res.Status == "timeout" {
							return &runFailedError{"task " + res.Status}
						}
					}
					return nil
				}
				if len(res.Items) < 2000 {
					time.Sleep(time.Second)
				}
			}
		},
	}
	out.Flags().BoolVarP(&follow, "follow", "f", false, "keep streaming until the task finishes")
	c.AddCommand(out)
	return c
}

func newGroupsCmd() *cobra.Command {
	c := &cobra.Command{Use: "groups", Aliases: []string{"device-groups"}, Short: "Device groups"}
	type group struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		MemberCount int    `json:"memberCount"`
	}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List device groups",
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
				Items []group `json:"items"`
			}
			if err := client.Do(http.MethodGet, "/device-groups", nil, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[group]{
				{Header: "ID", Value: func(g group) string { return g.ID }},
				{Header: "NAME", Value: func(g group) string { return g.Name }},
				{Header: "KIND", Value: func(g group) string { return g.Kind }},
				{Header: "DEVICES", Value: func(g group) string { return strconv.Itoa(g.MemberCount) }},
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "members <name|id>",
		Short: "List the current members of a group",
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
			t, err := parseTargets(client, []string{"group:" + args[0]})
			if err != nil {
				return err
			}
			var res struct {
				Items []device `json:"items"`
				Total int      `json:"total"`
			}
			if err := client.Do(http.MethodGet, "/device-groups/"+t.GroupIDs[0]+"/devices", url.Values{"limit": {"500"}}, nil, &res); err != nil {
				return err
			}
			return output.Render(cmd.OutOrStdout(), f, res, res.Items, []output.Column[device]{
				{Header: "ID", Value: func(d device) string { return d.ID }},
				{Header: "HOSTNAME", Value: func(d device) string { return d.Hostname }},
				{Header: "OS", Value: func(d device) string { return d.OS + " " + d.OSVersion }},
				{Header: "LAST SEEN", Value: func(d device) string { return deref(d.LastSeenAt) }},
			})
		},
	})
	return c
}
