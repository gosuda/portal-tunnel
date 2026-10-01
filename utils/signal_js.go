//go:build js

package utils

import "context"

// A browser has no process signals; the page's lifetime is the context's.
func SignalContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
