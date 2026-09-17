package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestNormalizePprofAddr(t *testing.T) {
	for name, test := range map[string]struct {
		enabled bool
		addr    string
		want    string
	}{
		"enabled without address gets loopback default": {enabled: true, want: DefaultPprofListenAddr},
		"enabled explicit address survives trimmed":     {enabled: true, addr: " 127.0.0.1:7070 ", want: "127.0.0.1:7070"},
		"enabled blank address counts as unset":         {enabled: true, addr: "   ", want: DefaultPprofListenAddr},
		// A disabled server must not inherit the default address either: the
		// caller starts nothing, but no address should exist to start.
		"disabled starts nothing": {want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizePprofAddr(test.enabled, test.addr); got != test.want {
				t.Fatalf("normalizePprofAddr(%v, %q) = %q, want %q", test.enabled, test.addr, got, test.want)
			}
		})
	}
}

// pprofTestAddrs returns loopback addresses outside the kernel's ephemeral
// range, so a released port cannot be stolen by a concurrent bind(":0")
// between shutdown and the re-bind assertion.
func pprofTestAddrs(t *testing.T) []string {
	t.Helper()
	lo, hi := 32768, 60999
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d %d", &lo, &hi); err != nil {
			t.Fatalf("parse ephemeral port range: %v", err)
		}
	}
	var addrs []string
	for port := 31000; port <= min(32100, lo-1); port++ {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", port))
	}
	for port := hi + 1; len(addrs) == 0 && port <= 65535; port++ {
		addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", port))
	}
	if len(addrs) == 0 {
		t.Skip("no non-ephemeral port band available for pprof tests")
	}
	return addrs
}

// startTestPprofServer starts the pprof server on the first free
// non-ephemeral address and fails the test on any non-bind error.
func startTestPprofServer(t *testing.T) (string, func(context.Context) error) {
	t.Helper()
	for _, addr := range pprofTestAddrs(t) {
		bound, shutdown, err := startPprofServer(context.Background(), addr)
		if err == nil {
			if bound.String() != addr {
				t.Fatalf("pprof server bound %s, want %s", bound, addr)
			}
			return addr, shutdown
		}
		if !strings.Contains(err.Error(), "listen pprof") {
			t.Fatalf("start pprof server: %v", err)
		}
	}
	t.Fatal("no free non-ephemeral pprof test address")
	return "", nil
}

func TestStartPprofServerServesRoutesAndReleasesPort(t *testing.T) {
	addr, shutdown := startTestPprofServer(t)

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
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("pprof port not released: %v", err)
	}
	listener.Close()
}

func TestStartPprofServerBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", pprofTestAddrs(t)[0])
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	_, _, err = startPprofServer(context.Background(), occupied.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "listen pprof") {
		t.Fatalf("start error=%v, want listen pprof bind failure", err)
	}
}
