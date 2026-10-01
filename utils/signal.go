package utils

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// SignalContext follows process termination signals where the runtime has them.
// A browser has no process signals, so its caller owns cancellation directly.
func SignalContext() (context.Context, context.CancelFunc) {
	if runtime.GOOS == "js" {
		return context.WithCancel(context.Background())
	}
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.Signal(1))
}
