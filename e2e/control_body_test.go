package e2e_test

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayClosesUnreadControlBodies(t *testing.T) {
	_, base, client := startPolicyRelay(t, t.TempDir(), "--cache-enabled=false")
	transport := client.Transport.(*http.Transport)
	for _, request := range []struct {
		method, path string
		status       int
	}{
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
		t.Run(request.method+" "+request.path, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", base.Host, transport.TLSClientConfig.Clone())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Leave almost all of the body unsent. The relay must terminate it
			// itself rather than wait for the client or the 30-second deadline.
			body := "{"
			if request.path == types.PathSDKRegisterChallenge {
				body = "{]" // Invalid JSON must not block in the decoder's Close.
			}
			if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4096\r\n\r\n%s", request.method, request.path, base.Host, body); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: request.method})
			if err != nil {
				t.Fatalf("response blocked on unread body: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != request.status || !response.Close {
				t.Fatalf("response = %d close=%v, want %d close=true", response.StatusCode, response.Close, request.status)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("relay did not close unread-body connection: %v", err)
			}
		})
	}
	t.Run("trickled body has an absolute deadline", func(t *testing.T) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", base.Host, transport.TLSClientConfig.Clone())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
			t.Fatal(err)
		}
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
		}()
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("trickled body outlived the read deadline: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || !response.Close {
			t.Fatalf("timed-out response = %d close=%v, want 400 close=true", response.StatusCode, response.Close)
		}
	})
}

func TestRelayMetricsEndpoint(t *testing.T) {
	_, base, client := startPolicyRelay(t, t.TempDir(), "--cache-enabled=false")
	deadline := time.Now().Add(7 * time.Second)
	for {
		response, err := client.Get(base.String() + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("metrics status = %d, want %d; body = %s", response.StatusCode, http.StatusOK, body)
		}
		if strings.Contains(string(body), "go_goroutines") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics response did not contain go_goroutines:\n%s", body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
