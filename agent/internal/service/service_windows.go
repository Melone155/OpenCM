//go:build windows

// Package service integrates the agent with the OS service manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	Name        = "OpenCMAgent"
	displayName = "OpenCM Agent"
	description = "OpenCM client management agent (inventory, jobs, software distribution)."
)

// IsService reports whether the process was started by the Service Control Manager.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct{ run func(ctx context.Context) }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.run(ctx)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case <-done:
			cancel()
			return false, 1 // unexpected exit → SCM recovery actions restart us
		}
	}
}

// RunService runs fn under the SCM until the service is stopped.
func RunService(fn func(ctx context.Context)) error {
	return svc.Run(Name, &handler{run: fn})
}

// Install registers the agent as an auto-start service (LocalSystem) with
// restart-on-failure and starts it.
func Install(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists – run uninstall first", Name)
	}
	s, err := m.CreateService(Name, exe, mgr.Config{
		DisplayName:      displayName,
		Description:      description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 24*60*60)
	return s.Start()
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service %s not installed", Name)
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return errors.Join(errors.New("delete service"), err)
	}
	return nil
}
