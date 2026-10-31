package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayMetricsAuthenticatedSnapshotAndHTTPLabels(t *testing.T) {
	api, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	handler := api.metrics.instrument(api.Handler())
	serve := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if got := serve(http.MethodGet, types.PathAdmin+"/metrics", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated scrape status = %d", got.Code)
	}
	if got := serve(http.MethodGet, "/metrics", ""); strings.Contains(got.Body.String(), "portal_relay_active_leases") {
		t.Fatal("public /metrics exposed relay statistics")
	}
	if got := serve("UNUSUAL", types.PathAdmin+"/unknown", "admin-test"); got.Code != http.StatusNotFound {
		t.Fatalf("unknown method status = %d", got.Code)
	}
	scrape := serve(http.MethodGet, types.PathAdmin+"/metrics", "admin-test")
	if scrape.Code != http.StatusOK {
		t.Fatalf("authenticated scrape status = %d: %s", scrape.Code, scrape.Body.String())
	}
	for _, line := range []string{
		"portal_relay_active_leases 0",
		"portal_relay_active_connections 0",
		"portal_relay_active_udp_flows 0",
		"portal_relay_forwarded_stream_bytes_total 0",
		`portal_relay_http_requests_total{code="401",method="get"} 1`,
		`portal_relay_http_requests_total{code="404",method="unknown"} 1`,
		`portal_relay_http_request_duration_seconds_count{code="401"} 1`,
	} {
		if !strings.Contains(scrape.Body.String(), line+"\n") {
			t.Errorf("scrape missing %q", line)
		}
	}
	if strings.Contains(scrape.Body.String(), "admin-test") {
		t.Fatal("admin token leaked into metrics")
	}
}

func TestRelayMetricsRegistriesAreIndependent(t *testing.T) {
	first, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, types.PathAdmin+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer admin-test")
	first.metrics.instrument(first.Handler()).ServeHTTP(httptest.NewRecorder(), req)
	scrape := httptest.NewRecorder()
	second.Handler().ServeHTTP(scrape, req)
	if scrape.Code != http.StatusOK || strings.Contains(scrape.Body.String(), "portal_relay_http_requests_total{") {
		t.Fatalf("second relay inherited first relay request metrics: %s", scrape.Body.String())
	}
}

func TestRelayMetricsConcurrentRequestsAndScrapes(t *testing.T) {
	api, _, err := newPolicyAPI(t, "")
	if err != nil {
		t.Fatal(err)
	}
	handler := api.metrics.instrument(api.Handler())
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, types.PathAdmin+"/unknown", nil)
			req.Header.Set("Authorization", "Bearer admin-test")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("request status = %d", rec.Code)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, types.PathAdmin+"/metrics", nil)
			req.Header.Set("Authorization", "Bearer admin-test")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("scrape status = %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	req := httptest.NewRequest(http.MethodGet, types.PathAdmin+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer admin-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `portal_relay_http_requests_total{code="404",method="get"} 20`+"\n") {
		t.Fatalf("concurrent request count missing from scrape: %s", rec.Body.String())
	}
}
