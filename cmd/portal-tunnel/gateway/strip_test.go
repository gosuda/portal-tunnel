package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStripRequestHeaders(t *testing.T) {
	t.Parallel()
	var gotHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handler, err := NewStripRequestHeaders(next, []string{"X-Custom", "Authorization"})
	if err != nil {
		t.Fatalf("NewStripRequestHeaders() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("X-Custom", "secret")
	req.Header.Set("Authorization", "Bearer abc")
	req.Header.Set("X-Keep", "keep")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatalf("X-Custom forwarded: %q", gotHeaders.Get("X-Custom"))
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Fatalf("Authorization forwarded: %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Keep") != "keep" {
		t.Fatalf("X-Keep = %q, want keep", gotHeaders.Get("X-Keep"))
	}
	// Case-insensitive: lowercase input is also stripped.
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Header.Set("x-custom", "secret")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if gotHeaders.Get("X-Custom") != "" {
		t.Fatal("x-custom forwarded after case-insensitive strip")
	}
}

func TestStripRequestHeadersRejectsHost(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, name := range []string{"Host", "X-Forwarded-Proto"} {
		if _, err := NewStripRequestHeaders(next, []string{name}); err == nil {
			t.Fatalf("NewStripRequestHeaders(%q) error = nil, want rejection", name)
		}
	}
}

func TestStripRequestHeadersRejectsInvalidNames(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, name := range []string{"", "  ", "X Custom", "X-Custom:"} {
		if _, err := NewStripRequestHeaders(next, []string{name}); err == nil {
			t.Fatalf("NewStripRequestHeaders(%q) error = nil, want invalid name error", name)
		}
	}
}

func TestStripRequestHeadersOnUpgrades(t *testing.T) {
	t.Parallel()
	gotStripped := make(chan string, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStripped <- r.Header.Get("X-Custom")
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack() error = %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: portal-test\r\n\r\n")
		_ = rw.Flush()
	})
	handler, err := NewStripRequestHeaders(inner, []string{"X-Custom"})
	if err != nil {
		t.Fatalf("NewStripRequestHeaders() error = %v", err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()

	conn, err := new(net.Dialer).DialContext(t.Context(), "tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: app.relay.example\r\nConnection: Upgrade\r\nUpgrade: portal-test\r\nX-Custom: forged\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade request error = %v", err)
	}
	select {
	case got := <-gotStripped:
		if got != "" {
			t.Fatalf("upgrade request X-Custom = %q, want stripped", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not receive request")
	}
}
