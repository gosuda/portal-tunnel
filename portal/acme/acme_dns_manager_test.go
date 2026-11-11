package acme

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

type publicIPTransport struct {
	err error
	ip  string
}

func (transport publicIPTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if transport.err != nil {
		return nil, transport.err
	}
	ip := cmp.Or(transport.ip, "203.0.113.10")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(ip)),
		Header:     make(http.Header),
	}, nil
}

func newEmbeddedDNSManager(t *testing.T, cfg Config) (*Manager, Config) {
	t.Helper()

	addressInUse := syscall.EADDRINUSE
	if runtime.GOOS == "windows" {
		addressInUse = syscall.Errno(10048)
	}
	const attempts = 5
	var lastErr error
	for range attempts {
		cfg.EmbeddedDNSPort = allocateNewEmbeddedDNSManagerPort(t)
		manager, err := NewManager(cfg)
		if err == nil {
			t.Cleanup(func() {
				if err := manager.Stop(context.Background()); err != nil {
					t.Errorf("Stop(): %v", err)
				}
			})
			return manager, cfg
		}
		var bindErr *os.SyscallError
		if !errors.As(err, &bindErr) || bindErr.Syscall != "bind" || !errors.Is(bindErr, addressInUse) {
			t.Fatalf("NewManager(): %v", err)
		}
		lastErr = err
	}
	t.Fatalf("NewManager() could not bind a DNS port after %d attempts: %v", attempts, lastErr)
	return nil, cfg
}

func allocateNewEmbeddedDNSManagerPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("allocate DNS probe port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release DNS probe port: %v", err)
	}
	return port
}
