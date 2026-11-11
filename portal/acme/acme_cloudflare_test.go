package acme

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestEnsureTLSMaterialRejectsDNSRecordUpdateFailure(t *testing.T) {
	server := httptest.NewTLSServer(rejectDNSRecordUpdate(t))
	t.Cleanup(server.Close)

	client := newDNSUpdateFailureClient(t, server)
	t.Cleanup(client.CloseIdleConnections)
	originalClient := utils.DefaultHTTPClient
	utils.DefaultHTTPClient = client
	t.Cleanup(func() { utils.DefaultHTTPClient = originalClient })

	manager := newTestManager(t, Config{
		BaseDomain:      "portal.example.com",
		KeyDir:          t.TempDir(),
		DNSProvider:     TypeCloudflare,
		CloudflareToken: "test-token",
	})
	err := manager.EnsureTLSMaterial(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ensure dns records: ensure A record") || !strings.Contains(err.Error(), "DNS record update rejected") {
		t.Fatalf("EnsureTLSMaterial() error = %v, want fatal DNS record update failure", err)
	}
	if manager.TLSMaterial() != nil {
		t.Fatal("EnsureTLSMaterial() loaded a certificate after a failed update")
	}
}

func rejectDNSRecordUpdate(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.cloudflare.com" {
			_, _ = io.WriteString(w, "203.0.113.10")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"test-zone","name":"portal.example.com"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/test-zone/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"test-record","type":"A","name":"portal.example.com","content":"198.51.100.1"}]}`)
		case r.Method == http.MethodPut && r.URL.Path == "/client/v4/zones/test-zone/dns_records/test-record":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"DNS record update rejected"}]}`)
		default:
			t.Errorf("unexpected DNS API request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func newDNSUpdateFailureClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	client := utils.NewHTTPClient(
		utils.WithHTTPTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	transport := client.Transport.(*http.Transport)
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	return client
}
