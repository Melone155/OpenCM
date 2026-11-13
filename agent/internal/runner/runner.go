// Package runner is the agent's main loop: heartbeat, inventory, certificate
// renewal, task execution (long poll) and self-update.
package runner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opencm/opencm/agent/internal/client"
	"github.com/opencm/opencm/agent/internal/identity"
	"github.com/opencm/opencm/agent/internal/inventory"
	"github.com/opencm/opencm/agent/internal/tasks"
	"github.com/opencm/opencm/agent/internal/updater"
)

const (
	inventoryInterval = 24 * time.Hour
	maxBackoff        = 15 * time.Minute
	revokedRetry      = 15 * time.Minute
	notEnrolledRetry  = time.Minute
	longPollWait      = 25 * time.Second
)

type Runner struct {
	Store   identity.Store
	Log     *slog.Logger
	Version string
	// Exe is the path of the running binary (target of self-updates).
	Exe string
	// Collect is replaceable for tests.
	Collect func(ctx context.Context) (*inventory.Inventory, error)
	// UpdateApplied is set when a new binary was installed; the process must restart.
	UpdateApplied bool

	started bool
	busy    atomic.Bool // a task is executing
}

// jitter spreads load: ±10 %.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d))
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run blocks until ctx is cancelled or an update was applied.
func (r *Runner) Run(ctx context.Context) {
	if r.Collect == nil {
		r.Collect = inventory.Collect
	}
	for ctx.Err() == nil && !r.UpdateApplied {
		state, err := r.Store.LoadState()
		if err != nil {
			if errors.Is(err, identity.ErrNotEnrolled) {
				r.Log.Warn("not enrolled yet, waiting", "retry", notEnrolledRetry.String())
			} else {
				r.Log.Error("cannot load state", "err", err)
			}
			if !sleep(ctx, notEnrolledRetry) {
				return
			}
			continue
		}
		r.session(ctx, state)
	}
}

// session runs heartbeat and task loops with one set of credentials until ctx is
// done, credentials change (renewal) or the device was revoked.
func (r *Runner) session(parent context.Context, state *identity.State) {
	tlsCfg, err := r.Store.TLSConfig()
	if err != nil {
		r.Log.Error("cannot load credentials", "err", err)
		sleep(parent, notEnrolledRetry)
		return
	}
	api := client.NewAgent(state.AgentURL, tlsCfg)
	defer api.Close()

	ctx, stop := context.WithCancel(parent)
	defer stop()

	key, err := r.signingKey(ctx, api)
	if err != nil {
		r.Log.Error("no task signing key – tasks will be refused", "err", err)
	}

	var wg sync.WaitGroup
	if key != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.taskLoop(ctx, api, state, key)
		}()
	}
	r.heartbeatLoop(ctx, api, state, key)
	stop()
	wg.Wait()
}

func (r *Runner) signingKey(ctx context.Context, api *client.Agent) (ed25519.PublicKey, error) {
	if k, err := r.Store.SigningKey(); err == nil {
		return k, nil
	}
	// Agents enrolled before M2: fetch over the authenticated mTLS channel.
	b64, err := api.SigningKey(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.Store.SaveSigningKey(b64); err != nil {
		return nil, err
	}
	return r.Store.SigningKey()
}

func (r *Runner) heartbeatLoop(ctx context.Context, api *client.Agent, state *identity.State, key ed25519.PublicKey) {
	interval := time.Duration(state.HeartbeatSeconds) * time.Second
	if interval < 10*time.Second {
		interval = time.Minute
	}
	backoff := interval
	hostname, _ := os.Hostname()
	r.Log.Info("agent session started", "deviceId", state.DeviceID, "endpoint", state.AgentURL, "interval", interval.String())

	for ctx.Err() == nil {
		hb, err := api.Heartbeat(ctx, client.HeartbeatRequest{
			AgentVersion:  r.Version,
			Hostname:      hostname,
			LoggedOnUsers: inventory.LoggedOnUsers(ctx),
			AgentStarted:  !r.started,
		})
		if err != nil {
			if client.IsRevoked(err) {
				r.Log.Error("server rejected this device (revoked or deleted) – re-enrol to restore", "err", err)
				sleep(ctx, revokedRetry)
				return // reload state: an operator may have re-enrolled meanwhile
			}
			backoff = min(backoff*2, maxBackoff)
			r.Log.Warn("heartbeat failed", "err", err, "retryIn", backoff.String())
			if !sleep(ctx, jitter(backoff)) {
				return
			}
			continue
		}
		r.started = true
		backoff = interval
		if hb.HeartbeatSeconds >= 10 && time.Duration(hb.HeartbeatSeconds)*time.Second != interval {
			interval = time.Duration(hb.HeartbeatSeconds) * time.Second
			state.HeartbeatSeconds = hb.HeartbeatSeconds
			_ = r.Store.SaveState(state)
		}

		// never update in the middle of a task – the offer is repeated with the next heartbeat
		if hb.Update != nil && key != nil && r.Exe != "" && !r.busy.Load() {
			r.Log.Info("agent update offered", "from", r.Version, "to", hb.Update.Version)
			err := updater.Apply(ctx, hb.Update, key, r.Exe, api.DownloadUpdate)
			if errors.Is(err, updater.ErrRestartRequired) {
				r.Log.Info("agent updated – restarting", "version", hb.Update.Version)
				r.UpdateApplied = true
				return
			}
			r.Log.Error("agent update failed", "err", err)
		}

		if hb.RenewCertificate {
			if err := r.renew(ctx, api, state); err != nil {
				r.Log.Error("certificate renewal failed", "err", err)
			} else {
				return // reconnect with new credentials
			}
		}

		if hb.InventoryRequested || time.Since(state.LastInventoryAt) > inventoryInterval {
			if err := r.inventory(ctx, api); err != nil {
				r.Log.Error("inventory failed", "err", err)
			} else {
				state.LastInventoryAt = time.Now().UTC()
				_ = r.Store.SaveState(state)
			}
		}

		if !sleep(ctx, jitter(interval)) {
			return
		}
	}
}

// taskLoop long-polls for tasks and executes them one at a time.
func (r *Runner) taskLoop(ctx context.Context, api *client.Agent, state *identity.State, key ed25519.PublicKey) {
	workDir, err := r.Store.WorkDir()
	if err != nil {
		r.Log.Error("cannot create work dir – tasks disabled", "err", err)
		return
	}
	seen := map[string]bool{} // taskId/attempt → replay protection within this process
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		env, err := api.NextTask(ctx, longPollWait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.Log.Warn("task poll failed", "err", err, "retryIn", backoff.String())
			if !sleep(ctx, jitter(backoff)) {
				return
			}
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = 5 * time.Second
		if env == nil {
			continue
		}
		r.handle(ctx, api, state, key, workDir, env, seen)
	}
}

func (r *Runner) handle(ctx context.Context, api *client.Agent, state *identity.State, key ed25519.PublicKey, workDir string, env *tasks.Envelope, seen map[string]bool) {
	p, err := tasks.Verify(env, key, state.DeviceID, time.Now())
	if err != nil {
		r.Log.Error("refusing task", "err", err)
		// Without a verified payload we only know the task id if the JSON is readable;
		// the server times the task out otherwise.
		if id := tasks.PeekTaskID(env); id != "" {
			msg := err.Error()
			_ = api.TaskResult(context.WithoutCancel(ctx), id, tasks.Result{Status: "failed", Error: &msg, Steps: []tasks.StepResult{}})
		}
		return
	}
	k := p.TaskID + "/" + strconv.Itoa(p.Attempt)
	if seen[k] {
		r.Log.Warn("ignoring replayed task", "taskId", p.TaskID)
		return
	}
	seen[k] = true

	r.busy.Store(true)
	defer r.busy.Store(false)
	log := r.Log.With("taskId", p.TaskID, "attempt", p.Attempt, "steps", len(p.Steps))
	cancel, err := api.StartTask(ctx, p.TaskID)
	if err != nil {
		log.Error("cannot start task", "err", err)
		return
	}
	var res tasks.Result
	if cancel {
		res = tasks.Result{Status: "cancelled", Steps: []tasks.StepResult{}}
	} else {
		log.Info("executing task")
		exec := &tasks.Executor{
			WorkDir: workDir,
			Report: func(c context.Context, chunks []tasks.Chunk) (bool, error) {
				return api.TaskOutput(c, p.TaskID, chunks)
			},
			Download: api.DownloadFile,
		}
		res = exec.Run(ctx, p)
	}
	// deliver the result even during shutdown; retry a few times
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer rcancel()
	for i := 0; i < 5; i++ {
		err = api.TaskResult(rctx, p.TaskID, res)
		var se *client.StatusError
		if err == nil || (errors.As(err, &se) && se.Code >= 400 && se.Code < 500) {
			break
		}
		sleep(rctx, time.Duration(i+1)*2*time.Second)
	}
	log.Info("task finished", "status", res.Status, "err", err)
}

func (r *Runner) inventory(ctx context.Context, api *client.Agent) error {
	start := time.Now()
	inv, err := r.Collect(ctx)
	if err != nil {
		return err
	}
	if err := api.SubmitInventory(ctx, inv); err != nil {
		return err
	}
	r.Log.Info("inventory sent", "software", len(inv.Software), "services", len(inv.Services), "took", time.Since(start).Round(time.Millisecond).String())
	return nil
}

func (r *Runner) renew(ctx context.Context, api *client.Agent, state *identity.State) error {
	keyPEM, csrPEM, err := identity.NewKeyAndCSR(state.DeviceID)
	if err != nil {
		return err
	}
	res, err := api.Renew(ctx, string(csrPEM))
	if err != nil {
		return err
	}
	if err := r.Store.SaveCredentials(keyPEM, []byte(res.Certificate), []byte(res.CACertificate)); err != nil {
		return err
	}
	state.CertExpiresAt = res.ExpiresAt
	r.Log.Info("certificate renewed", "expiresAt", res.ExpiresAt)
	return r.Store.SaveState(state)
}
