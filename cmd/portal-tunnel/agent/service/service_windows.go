//go:build windows

package service

import (
	"context"
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func Install(ctx context.Context, def Definition) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	cfg := mgr.Config{
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      def.DisplayName,
		Description:      def.Description,
		DelayedAutoStart: true,
	}
	s, err := m.OpenService(def.Name)
	if err == nil {
		defer s.Close()
		existing, cfgErr := s.Config()
		if cfgErr != nil {
			return cfgErr
		}
		cfg = existing
		cfg.StartType = mgr.StartAutomatic
		cfg.ErrorControl = mgr.ErrorNormal
		cfg.DisplayName = def.DisplayName
		cfg.Description = def.Description
		cfg.DelayedAutoStart = true
		cfg.BinaryPathName = windowsCommandLine(def)
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
		return configureWindowsRecovery(s)
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	s, err = m.CreateService(def.Name, def.Executable, cfg, def.Args...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := configureWindowsRecovery(s); err != nil {
		return err
	}
	return ctx.Err()
}

func Start(ctx context.Context, name string) error {
	s, err := openService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	err = s.Start()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return waitWindowsService(ctx, s, svc.Running)
}

func Stop(ctx context.Context, name string) error {
	s, err := openService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		return waitWindowsService(ctx, s, svc.Stopped)
	}
	return ctx.Err()
}

func StopDisable(ctx context.Context, name string) error {
	s, err := openService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer s.Close()

	cfg, err := s.Config()
	if err == nil {
		cfg.StartType = mgr.StartDisabled
		_ = s.UpdateConfig(cfg)
	}
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		return waitWindowsService(ctx, s, svc.Stopped)
	}
	return ctx.Err()
}

func openService(name string) (*mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	s, err := m.OpenService(name)
	_ = m.Disconnect()
	return s, err
}

func waitWindowsService(ctx context.Context, s *mgr.Service, want svc.State) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func windowsCommandLine(def Definition) string {
	line := syscall.EscapeArg(def.Executable)
	for _, arg := range def.Args {
		line += " " + syscall.EscapeArg(arg)
	}
	return line
}

func configureWindowsRecovery(s *mgr.Service) error {
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 60); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(false)
}

func Run(ctx context.Context, name string, run func(context.Context) error) error {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		return run(ctx)
	}
	return svc.Run(name, windowsServiceHandler{ctx: ctx, run: run})
}

type windowsServiceHandler struct {
	ctx context.Context
	run func(context.Context) error
}

func (h windowsServiceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()

	errCh := make(chan error, 1)
	status <- svc.Status{State: svc.StartPending}
	go func() {
		errCh <- h.run(ctx)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				return false, 1
			}
			return false, 0
		}
	}
}
