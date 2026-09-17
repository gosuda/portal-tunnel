package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultPprofListenAddr is the loopback address the pprof diagnostics server
// binds when --pprof-addr is not supplied.
const DefaultPprofListenAddr = "127.0.0.1:6060"

// normalizePprofAddr trims the flag value and applies the default when the
// server is enabled but no address was supplied.
func normalizePprofAddr(enabled bool, addr string) string {
	addr = strings.TrimSpace(addr)
	if enabled && addr == "" {
		return DefaultPprofListenAddr
	}
	return addr
}

// newPprofServer builds the pprof diagnostics HTTP server with the routes the
// relay used to mount internally.
func newPprofServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// startPprofServer binds addr synchronously so a bind failure aborts startup,
// then serves in the background. The returned shutdown func drains in-flight
// requests.
func startPprofServer(ctx context.Context, addr string) (net.Addr, func(context.Context) error, error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen pprof: %w", err)
	}
	server := newPprofServer()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Error().Err(err).Msg("serve pprof")
		}
	}()
	return listener.Addr(), server.Shutdown, nil
}
