//go:build !linux && !darwin && !windows

package service

import (
	"context"
	"errors"
)

var (
	errPortalAgentServiceInstallNotSupported = errors.New("portal agent service install is not supported on this OS")
	errPortalAgentServiceStartNotSupported   = errors.New("portal agent service start is not supported on this OS")
	errPortalAgentServiceStopNotSupported    = errors.New("portal agent service stop is not supported on this OS")
)

func Install(context.Context, Definition) error {
	return errPortalAgentServiceInstallNotSupported
}

func Start(context.Context, string) error {
	return errPortalAgentServiceStartNotSupported
}

func Stop(context.Context, string) error {
	return errPortalAgentServiceStopNotSupported
}

func StopDisable(context.Context, string) error {
	return errPortalAgentServiceStopNotSupported
}

func Run(ctx context.Context, name string, run func(context.Context) error) error {
	return run(ctx)
}
