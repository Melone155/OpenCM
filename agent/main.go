// Command opencm-agent runs on managed devices. It only ever opens outbound
// connections to the OpenCM server: enrolment via the public HTTPS API, then
// heartbeat/inventory via the mTLS agent endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/opencm/opencm/agent/internal/client"
	"github.com/opencm/opencm/agent/internal/config"
	"github.com/opencm/opencm/agent/internal/identity"
	"github.com/opencm/opencm/agent/internal/inventory"
	"github.com/opencm/opencm/agent/internal/runner"
	"github.com/opencm/opencm/agent/internal/service"
	"github.com/opencm/opencm/agent/internal/updater"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

// exitRestart is returned after a self-update so the service manager restarts the agent.
const exitRestart = 3

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("opencm-agent %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	case "run":
		err = runCmd(os.Args[2:])
	case "enroll":
		err = enrollCmd(os.Args[2:])
	case "install":
		err = installCmd()
	case "uninstall":
		err = service.Uninstall()
	case "status":
		err = statusCmd(os.Args[2:])
	case "inventory":
		err = inventoryCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: opencm-agent <command> [flags]

Commands:
  enroll     register with a server:  enroll --server https://cm.example.org --token <token> [--ca-file ca.pem]
  install    install and start as Windows service / systemd unit / launchd daemon
  uninstall  stop and remove the service
  run        run the agent in the foreground (used by the service manager)
  status     show enrolment state
  inventory  collect the local inventory and print it as JSON (nothing is sent)
  version    print version

Default config file: %s
`, config.DefaultPath())
}

func requireAdmin() error {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return errors.New("this command must be run as root")
	}
	return nil
}

func enrollCmd(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "server URL (https://…)")
	token := fs.String("token", "", "enrollment token")
	caFile := fs.String("ca-file", "", "additional CA certificate (PEM) for the server's public certificate")
	pin := fs.String("server-pin", "", "sha256:<hex> of the server's agent CA and signing key (set by the generated install script; replaces the HTTPS certificate check)")
	cfgPath := fs.String("config", config.DefaultPath(), "path to agent config")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		return errors.New("--server and --token are required")
	}
	if err := requireAdmin(); err != nil {
		return err
	}

	// Take over / verify the configuration directory first. If it existed before and belonged
	// to another user, nothing in it is trusted – in particular not a planted agent.json
	// that would point the data directory somewhere else.
	trustedBefore, err := identity.PrepareConfigDir(filepath.Dir(*cfgPath))
	if err != nil {
		return fmt.Errorf("prepare config dir: %w", err)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil || cfg.ServerURL != *server || !trustedBefore {
		if cfg, err = config.New(*server); err != nil {
			return err
		}
	}
	store := identity.Store{Dir: cfg.DataDir}
	if err := store.Init(); err != nil {
		return fmt.Errorf("prepare data dir: %w", err)
	}

	var extraCA []byte
	if *caFile != "" {
		if extraCA, err = os.ReadFile(*caFile); err != nil {
			return err
		}
	}
	machineID, err := inventory.MachineID()
	if err != nil {
		return fmt.Errorf("determine machine id: %w", err)
	}
	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := identity.NewKeyAndCSR(hostname)
	if err != nil {
		return err
	}
	osName := map[string]string{"windows": "windows", "linux": "linux", "darwin": "macos"}[runtime.GOOS]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := client.Enroll(ctx, *server, extraCA, *pin, client.EnrollRequest{
		Token: *token, CSR: string(csrPEM), Hostname: hostname, OS: osName, OSVersion: inventory.OSVersion(),
		Arch: runtime.GOARCH, AgentVersion: Version, MachineID: machineID,
	})
	if err != nil {
		return fmt.Errorf("enrolment failed: %w", err)
	}
	if err := store.SaveCredentials(keyPEM, []byte(res.Certificate), []byte(res.CACertificate)); err != nil {
		return err
	}
	if res.SigningPublicKey != "" {
		if err := store.SaveSigningKey(res.SigningPublicKey); err != nil {
			return fmt.Errorf("store signing key: %w", err)
		}
	}
	if err := store.SaveState(&identity.State{
		DeviceID: res.DeviceID, ServerURL: cfg.ServerURL, AgentURL: res.AgentURL,
		HeartbeatSeconds: res.HeartbeatSeconds, CertExpiresAt: res.CertificateExpiresAt,
	}); err != nil {
		return err
	}
	cfg.HeartbeatSeconds = res.HeartbeatSeconds
	if err := config.Save(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("Enrolled as device %s (endpoint %s). Next: `opencm-agent install`.\n", res.DeviceID, res.AgentURL)
	return nil
}

func installCmd() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := service.Install(exe); err != nil {
		return err
	}
	fmt.Println("Service installed and started.")
	return nil
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "path to agent config")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	st, err := identity.Store{Dir: cfg.DataDir}.LoadState()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

func inventoryCmd(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	compact := fs.Bool("compact", false, "single-line JSON")
	_ = fs.Parse(args)
	inv, err := inventory.Collect(context.Background())
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	if !*compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(inv)
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "path to agent config (JSON)")
	_ = fs.Parse(args)

	// The agent runs as SYSTEM/root: never read configuration or keys an unprivileged user controls.
	if err := identity.AssertTrusted(filepath.Dir(*cfgPath), *cfgPath); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := identity.AssertTrusted(filepath.Dir(cfg.DataDir), cfg.DataDir); err != nil {
		return err
	}

	var out io.Writer = os.Stdout
	if service.IsService() {
		// Windows services have no stdout: log to a file next to the config.
		f, err := openLogFile(filepath.Join(filepath.Dir(*cfgPath), "logs", "agent.log"))
		if err == nil {
			defer f.Close()
			out = f
		}
	}
	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	log.Info("agent starting", "version", Version, "os", runtime.GOOS, "arch", runtime.GOARCH, "server", cfg.ServerURL)

	exe, _ := os.Executable()
	if exe != "" {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		updater.Cleanup(exe) // leftover from a previous self-update (Windows)
	}
	r := &runner.Runner{Store: identity.Store{Dir: cfg.DataDir}, Log: log, Version: Version, Exe: exe}
	if service.IsService() {
		// When Run returns after a self-update the service exits with an error code and
		// the SCM recovery actions start the new binary.
		return service.RunService(r.Run)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r.Run(ctx)
	if r.UpdateApplied {
		log.Info("exiting for restart after self-update")
		os.Exit(exitRestart) // systemd (Restart=always) / launchd (KeepAlive) start the new binary
	}
	log.Info("agent stopped")
	return nil
}

// openLogFile opens the log file, rotating it once it exceeds 10 MiB.
func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
		_ = os.Rename(path, strings.TrimSuffix(path, ".log")+".1.log")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
