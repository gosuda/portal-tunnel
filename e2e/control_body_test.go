package e2e_test

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type controlRoute struct {
	method, path string
	status       int
}

func dialControlConn(t *testing.T, base *url.URL, transport *http.Transport, deadline time.Time) net.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", base.Host, transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return conn
}

func verifyUnreadResponseClosed(t *testing.T, reader *bufio.Reader, response *http.Response, route controlRoute) {
	t.Helper()
	if response.StatusCode != route.status || !response.Close {
		t.Fatalf("response = %d close=%v, want %d close=true", response.StatusCode, response.Close, route.status)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("relay did not close unread-body connection: %v", err)
	}
}

func checkUnreadBodyClosed(t *testing.T, base *url.URL, transport *http.Transport, route controlRoute) {
	t.Helper()
	conn := dialControlConn(t, base, transport, time.Now().Add(2*time.Second))
	defer conn.Close()
	body := "{"
	if route.path == types.PathSDKRegisterChallenge {
		body = "{]"
	}
	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4096\r\n\r\n%s", route.method, route.path, base.Host, body); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: route.method})
	if err != nil {
		t.Fatalf("response blocked on unread body: %v", err)
	}
	defer response.Body.Close()
	verifyUnreadResponseClosed(t, reader, response, route)
}

func trickleRequestBody(conn net.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if _, err := conn.Write([]byte(" ")); err != nil {
				return
			}
		}
	}
}

func checkTrickledBodyDeadline(t *testing.T, base *url.URL, transport *http.Transport) {
	t.Helper()
	conn := dialControlConn(t, base, transport, time.Now().Add(40*time.Second))
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4096\r\n\r\n{", types.PathSDKRegisterChallenge, base.Host); err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	defer func() {
		close(stop)
		_ = conn.Close()
		<-done
	}()
	go func() {
		defer close(done)
		trickleRequestBody(conn, stop)
	}()
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("trickled body outlived the read deadline: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || !response.Close {
		t.Fatalf("timed-out response = %d close=%v, want 400 close=true", response.StatusCode, response.Close)
	}
}

func TestRelayClosesUnreadControlBodies(t *testing.T) {
	_, base, client := startPolicyRelay(t, t.TempDir(), "--cache-enabled=false")
	transport := client.Transport.(*http.Transport)
	for _, route := range []controlRoute{
		{http.MethodPost, types.PathHealthz, http.StatusOK},
		{http.MethodPost, "/api//healthz", http.StatusTemporaryRedirect},
		{http.MethodPost, types.PathSDKConnect, http.StatusMethodNotAllowed},
		{http.MethodGet, types.PathSDKRegister, http.StatusMethodNotAllowed},
		{http.MethodGet, types.PathSDKConnect, http.StatusBadRequest},
		{http.MethodOptions, types.PathSDKRegister, http.StatusNoContent},
		{http.MethodPost, types.PathV1Sign, http.StatusForbidden},
		{http.MethodPost, types.PathPolicy, http.StatusUnauthorized},
		{http.MethodPost, types.PathSDKRegisterChallenge, http.StatusBadRequest},
		{http.MethodPost, types.PathSDKCache, http.StatusForbidden},
		{http.MethodPut, types.PathSDKCache, http.StatusForbidden},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			checkUnreadBodyClosed(t, base, transport, route)
		})
	}
	t.Run("trickled body has an absolute deadline", func(t *testing.T) {
		checkTrickledBodyDeadline(t, base, transport)
	})
}
