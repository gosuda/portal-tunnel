package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// namespaceService exercises the public HTTP server against an ordinary h1-only
// origin. It intentionally does not replace any production transport or issuer.
func namespaceService(t *testing.T, h *harness, id types.Identity, body string, opts ...sdk.Option) (*sdk.Exposure, sdk.RelayStatus) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("origin protocol = %s, want HTTP/1.1", r.Proto)
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	target, _ := url.Parse(origin.URL)
	exposure, err := sdk.Expose(t.Context(), id, []string{"https://" + h.sniAddr}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sdk.RunHTTP(t.Context(), exposure, httputil.NewSingleHostReverseProxy(target), "") }()
	t.Cleanup(func() {
		_ = exposure.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("HTTP service did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(ctx)
	if err != nil || len(ready) != 1 {
		t.Fatalf("namespace readiness = %+v, %v", ready, err)
	}
	for ready[0].PublicURL == "" {
		select {
		case <-ctx.Done():
			t.Fatalf("canonical URL not ready: %+v", exposure.Relays())
		case <-exposure.Updates():
			ready = exposure.Relays()
		}
	}
	return exposure, ready[0]
}

func namespaceResponse(t *testing.T, h *harness, publicURL, body string, h2 bool) *x509.Certificate {
	t.Helper()
	client, transport, ok := tenantTLSClient(h.sniAddr, h.certificate)
	if !ok {
		t.Fatal("load tenant trust")
	}
	transport.ForceAttemptHTTP2 = h2
	if h2 {
		transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	defer transport.CloseIdleConnections()
	response, err := client.Get(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	wantProto := 1
	if h2 {
		wantProto = 2
	}
	if err != nil || response.StatusCode != 200 || string(data) != body || response.ProtoMajor != wantProto {
		t.Fatalf("namespace response: status=%d body=%q proto=%s error=%v", response.StatusCode, data, response.Proto, err)
	}
	if response.Header.Get("Cache-Control") != "public, max-age=60" {
		t.Fatal("browser cache policy was lost")
	}
	return response.TLS.PeerCertificates[0]
}

func TestServiceNamespaceHTTPAndSiblingIsolation(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL() // Another identity already owns e2e.localhost.
	id, err := identity.Generate("e2e")
	if err != nil {
		t.Fatal(err)
	}
	first, blog := namespaceService(t, h, id, "blog", sdk.WithAutomaticTLS(t.TempDir(), true))
	if blog.AliasURL != "" {
		t.Fatalf("global alias collision acquired alias: %+v", blog)
	}
	id.Name = "api"
	_, api := namespaceService(t, h, id, "api", sdk.WithAutomaticTLS(t.TempDir(), true))
	address := strings.ToLower(strings.TrimPrefix(id.Address, "0x"))
	var leaves []*x509.Certificate
	for _, service := range []struct {
		status     sdk.RelayStatus
		name, body string
	}{{blog, "e2e", "blog"}, {api, "api", "api"}} {
		parsed, err := url.Parse(service.status.PublicURL)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Hostname() != service.name+"."+address+".localhost" {
			t.Fatalf("canonical URL = %s", parsed)
		}
		for _, h2 := range []bool{false, true} {
			leaf := namespaceResponse(t, h, service.status.PublicURL, service.body, h2)
			if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != parsed.Hostname() || leaf.IsCA {
				t.Fatalf("canonical leaf SANs=%v CA=%v", leaf.DNSNames, leaf.IsCA)
			}
			if !h2 {
				leaves = append(leaves, leaf)
			}
		}
		client, transport, _ := tenantTLSClient(h.sniAddr, h.certificate)
		transport.ForceAttemptHTTP2 = true
		transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, service.status.PublicURL, nil)
		req.Host = "other." + address + ".localhost"
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		transport.CloseIdleConnections()
		if response.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("sibling authority mismatch = %d", response.StatusCode)
		}
		conn, err := sdk.DialCanonicalTLS(t.Context(), h.sniAddr, parsed.Hostname(), &tls.Config{RootCAs: loadRelayCertPool(t, h.certificate)})
		if err != nil {
			t.Fatalf("native canonical binding: %v", err)
		}
		conn.Close()
	}
	if bytes.Equal(leaves[0].RawSubjectPublicKeyInfo, leaves[1].RawSubjectPublicKeyInfo) {
		t.Fatal("sibling services share leaf private key")
	}
	if api.AliasURL == "" || api.LegacyURL == "" {
		t.Fatalf("compatibility URLs missing: %+v", api)
	}
	for _, legacy := range []string{api.AliasURL, api.LegacyURL} {
		leaf := namespaceResponse(t, h, legacy, "api", false)
		if !leaf.IsCA {
			t.Fatal("friendly/legacy path switched to tenant leaf")
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	namespaceResponse(t, h, api.PublicURL, "api", true)
	if _, ok := tenantGet(h.sniAddr, h.certificate, blog.PublicURL); ok {
		t.Fatal("closed canonical returned retained response")
	}
}

func TestUnnamedNamespaceReservesDefaultService(t *testing.T) {
	h := newHarness(t)
	h.waitForPublicURL()
	id, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	_, ready := namespaceService(t, h, id, "unnamed", sdk.WithAutomaticTLS(t.TempDir(), true))
	parsed, _ := url.Parse(ready.PublicURL)
	address := strings.ToLower(strings.TrimPrefix(id.Address, "0x"))
	if parsed.Hostname() != "default."+address+".localhost" || ready.AliasURL != "" {
		t.Fatalf("unnamed canonical=%+v", ready)
	}
	namespaceResponse(t, h, ready.PublicURL, "unnamed", true)
	id.Name = "default"
	reserved, err := sdk.Expose(t.Context(), id, []string{"https://" + h.sniAddr}, sdk.WithAutomaticTLS(t.TempDir(), true))
	if err == nil {
		defer reserved.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err = reserved.WaitReady(ctx)
	}
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("explicit reserved service should be rejected: %v", err)
	}
	namespaceResponse(t, h, ready.PublicURL, "unnamed", true)
}
