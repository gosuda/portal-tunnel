//go:build !js

package utils

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
}
