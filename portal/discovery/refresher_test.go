package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestRefresherRefreshHTTPSIsParallel(t *testing.T) {
	const n = 5

	var received atomic.Int32
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	servers := make([]*httptest.Server, n)
	urls := make([]string, n)
	for i := range n {
		url := ""
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != types.PathDiscovery {
				http.NotFound(w, r)
				return
			}
			c := current.Add(1)
			if c > maxConcurrent.Load() {
				maxConcurrent.Store(c)
			}
			// Hold the request open so concurrent requests must overlap if
			// the refresher is truly parallel.
			time.Sleep(50 * time.Millisecond)
			current.Add(-1)
			received.Add(1)

			// Each server returns a signed descriptor for itself so the
			// authoritative refresh succeeds.
			desc := mustRelayDescriptor(t, url)
			utils.WriteAPIData(w, http.StatusOK, types.DiscoveryResponse{
				ProtocolVersion: types.DiscoveryVersion,
				Relays:          []types.RelayDescriptor{desc},
			})
		}))
		url = srv.URL
		servers[i] = srv
		urls[i] = srv.URL
	}
	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	set := NewRelaySet(urls)
	refresher := NewRefresher(set, nil)

	// Trust all test server certificates and allow reuse of idle connections.
	baseTransport := servers[0].Client().Transport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig.InsecureSkipVerify = true
	refresher.httpClient = &http.Client{
		Transport: baseTransport,
		Timeout:   defaultRequestTimeout,
	}

	if err := refresher.refreshHTTPS(testContext(t)); err != nil {
		t.Fatalf("refreshHTTPS() error = %v", err)
	}

	if got := received.Load(); got != n {
		t.Fatalf("received %d requests, want %d", got, n)
	}
	if max := maxConcurrent.Load(); max < 2 {
		t.Fatalf("max concurrent requests = %d, want at least 2 (parallel refresh)", max)
	}

	for _, relayURL := range urls {
		found := false
		for _, state := range set.AllRelays() {
			if state.Descriptor.APIHTTPSAddr == relayURL {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("relay %q was not ingested after parallel refresh", relayURL)
		}
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
