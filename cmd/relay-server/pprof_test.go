package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizePprofAddr(t *testing.T) {
	for name, test := range map[string]struct {
		addr string
		want string
	}{
		"without address gets loopback default": {want: DefaultPprofListenAddr},
		"explicit address survives trimmed":     {addr: " 127.0.0.1:7070 ", want: "127.0.0.1:7070"},
		"blank address counts as unset":         {addr: "   ", want: DefaultPprofListenAddr},
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizePprofAddr(test.addr); got != test.want {
				t.Fatalf("normalizePprofAddr(%q) = %q, want %q", test.addr, got, test.want)
			}
		})
	}
}

// startTestPprofServer starts the diagnostics server on a loopback wildcard
// port and returns the concrete address it bound.
func startTestPprofServer(t *testing.T) (string, func(context.Context) error, <-chan error) {
	t.Helper()
	bound, shutdown, serveErrs, err := startPprofServer(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start pprof server: %v", err)
	}
	return bound.String(), shutdown, serveErrs
}

func TestStartPprofServerServesRoutesAndReleasesPort(t *testing.T) {
	addr, shutdown, serveErrs := startTestPprofServer(t)

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", path, resp.StatusCode, http.StatusOK)
		}
	}

	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown pprof server: %v", err)
	}
	// A clean shutdown is not a serve failure: nothing may be reported.
	select {
	case err := <-serveErrs:
		t.Fatalf("clean shutdown reported serve error: %v", err)
	default:
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("pprof port not released: %v", err)
	}
	listener.Close()
}

func TestStartPprofServerBindFailure(t *testing.T) {
	// Occupy a wildcard-assigned loopback port, then attempt the same address:
	// simple and deterministic, with no port-range bookkeeping.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	_, _, _, err = startPprofServer(context.Background(), occupied.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "listen pprof") {
		t.Fatalf("start error=%v, want listen pprof bind failure", err)
	}
}
