package sdk

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunHTTPTranslatesHTTP2AndRejectsSiblingAuthority(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("backend received %s, want HTTP/1.1", r.Proto)
		}
		_, _ = io.WriteString(w, "local backend")
	}))
	defer backend.Close()
	handler, err := NewHTTPRoutes([]HTTPRouteConfig{{Prefix: "/", Upstream: backend.URL}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := fixture.TLS.Clone()
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	clientTLS := fixture.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clientTLS.ServerName = "example.com"
	fixture.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunHTTP(ctx, tls.NewListener(listener, serverTLS), handler, "") }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunHTTP: %v", err)
		}
	}()
	for _, h2 := range []bool{false, true} {
		transport := &http.Transport{TLSClientConfig: clientTLS.Clone(), ForceAttemptHTTP2: h2}
		client := &http.Client{Transport: transport}
		for _, authority := range []string{"example.com", "sibling.example.com"} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.Addr().String()+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = authority
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if resp.ProtoMajor != wantProtocol {
				t.Fatalf("protocol = %s, want major %d", resp.Proto, wantProtocol)
			}
			if authority == "example.com" {
				if resp.StatusCode != http.StatusOK || string(body) != "local backend" {
					t.Fatalf("proxy response: %s %q", resp.Status, body)
				}
			} else if resp.StatusCode != http.StatusMisdirectedRequest {
				t.Fatalf("sibling authority = %s, want 421", resp.Status)
			}
		}
		transport.CloseIdleConnections()
	}
}
