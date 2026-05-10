//go:build !linux && !darwin && !windows

package service

import (
	"context"
	"errors"
)

func Install(context.Context, Definition) error {
	return errors.New("portal agent service install is not supported on this OS")
}

func Start(context.Context, string) error {
	return errors.New("portal agent service start is not supported on this OS")
}

func Stop(context.Context, string) error {
	return errors.New("portal agent service stop is not supported on this OS")
}

func StopDisable(context.Context, string) error {
	return errors.New("portal agent service stop is not supported on this OS")
}

func Run(ctx context.Context, name string, run func(context.Context) error) error {
	return run(ctx)
}
