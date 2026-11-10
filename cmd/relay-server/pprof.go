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
)

const DefaultPprofListenAddr = "127.0.0.1:6060"

func normalizePprofAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return DefaultPprofListenAddr
	}
	return addr
}

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
		ReadTimeout:       10 * time.Second,
	}
}

func startPprofServer(ctx context.Context, addr string) (net.Addr, func(context.Context) error, <-chan error, error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen pprof: %w", err)
	}
	server := newPprofServer()
	serveErrs := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			serveErrs <- err
		}
	}()
	return listener.Addr(), server.Shutdown, serveErrs, nil
}

func hostPortOrLoopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
