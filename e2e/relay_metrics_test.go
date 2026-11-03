package e2e_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRelayCommandMetricsForwardedBytesAndReset(t *testing.T) {
	stateDir := t.TempDir()
	ctx, base, client := startPolicyRelay(t, stateDir, "--cache-enabled=false")
	unauthorized, err := client.Get(base.String() + types.PathAdmin + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d", unauthorized.StatusCode)
	}
	public, err := client.Get(base.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	publicBody, err := io.ReadAll(public.Body)
	_ = public.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicBody), "portal_relay_forwarded_stream_bytes_total") {
		t.Fatal("public /metrics exposed relay statistics")
	}
	scrapeMetric := func(baseURL string, client *http.Client, metric string) float64 {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+types.PathAdmin+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer admin-test")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("metrics status = %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		prefix := metric + " "
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, prefix) {
				value, err := strconv.ParseFloat(strings.TrimPrefix(line, prefix), 64)
				if err != nil {
					t.Fatalf("parse %s: %v", metric, err)
				}
				return value
			}
		}
		t.Fatalf("%s missing: %s", metric, body)
		return 0
	}
	const bytesMetric = "portal_relay_forwarded_stream_bytes_total"
	if got := scrapeMetric(base.String(), client, bytesMetric); got != 0 {
		t.Fatalf("initial forwarded bytes = %v, want 0", got)
	}

	id, err := identity.Generate("metrics")
	if err != nil {
		t.Fatal(err)
	}
	exposure, err := sdk.Expose(ctx, id, []string{"https://localhost:" + base.Port()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exposure.Close() })
	go func() {
		_ = sdk.RunHTTP(ctx, exposure, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "relay metrics payload")
		}), "")
	}()
	readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ready, err := exposure.WaitReady(readyCtx)
	if err != nil || len(ready) != 1 {
		t.Fatalf("exposure ready: %v, relays=%d", err, len(ready))
	}
	if got := scrapeMetric(base.String(), client, "portal_relay_active_leases"); got != 1 {
		t.Fatalf("active leases after ready = %v, want 1", got)
	}
	tenantTransport := client.Transport.(*http.Transport).Clone()
	tenantTransport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, base.Host)
	}
	defer tenantTransport.CloseIdleConnections()
	tenantClient := &http.Client{Transport: tenantTransport, Timeout: 5 * time.Second}
	request := func() {
		t.Helper()
		resp, err := tenantClient.Get(ready[0].PublicURL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK || string(body) != "relay metrics payload" {
			t.Fatalf("tenant response: status=%d body=%q err=%v", resp.StatusCode, body, err)
		}
	}
	request()
	first := scrapeMetric(base.String(), client, bytesMetric)
	if first <= 0 {
		t.Fatalf("forwarded bytes after first request = %v, want positive", first)
	}
	request()
	second := scrapeMetric(base.String(), client, bytesMetric)
	if second <= first {
		t.Fatalf("forwarded bytes did not increase: first=%v second=%v", first, second)
	}

	_, freshBase, freshClient := startPolicyRelay(t, t.TempDir(), "--cache-enabled=false")
	if got := scrapeMetric(freshBase.String(), freshClient, bytesMetric); got != 0 {
		t.Fatalf("new relay forwarded bytes = %v, want 0", got)
	}
	if got := scrapeMetric(freshBase.String(), freshClient, "portal_relay_active_leases"); got != 0 {
		t.Fatalf("new relay active leases = %v, want 0", got)
	}
}
