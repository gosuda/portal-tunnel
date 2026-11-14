package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

type localTransport struct {
	base http.RoundTripper
	url  *url.URL
}

func (t localTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = t.url.Scheme, t.url.Host
	return t.base.RoundTrip(req)
}

func TestChallengeLostResponse(t *testing.T)      { testChallengeLifecycle(t, "lost response") }
func TestChallengeSuccessfulCleanup(t *testing.T) { testChallengeLifecycle(t, "success") }
func TestChallengePreexistingValue(t *testing.T)  { testChallengeLifecycle(t, "preexisting") }

func testChallengeLifecycle(t *testing.T, mode string) {
	t.Helper()
	var mu sync.Mutex
	records := []dnsRecord{{ID: "wrong-name", Type: "TXT", Name: "other.example.com", Content: "value"}}
	if mode == "preexisting" {
		records = append(records, dnsRecord{ID: "existing", Type: "TXT", Name: "_acme-challenge.example.com", Content: `"value"`})
	}
	created := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/client/v4/zones/zone-id/dns_records") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			defer mu.Unlock()
			page := []dnsRecord{{ID: "other", Type: "TXT", Name: "_acme-challenge.example.com", Content: "value-other"}}
			if r.URL.Query().Get("page") == "2" {
				page = records
			}
			_ = json.NewEncoder(w).Encode(recordsResult{Success: true, Result: page, Info: resultInfo{TotalPages: 2}})
		case http.MethodPost:
			var req struct {
				dnsRecord
				TTL int `json:"ttl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.TTL != 420 || req.Content != `"value"` || req.Name != "_acme-challenge.example.com" {
				t.Errorf("unexpected create: %+v", req)
			}
			req.ID = "new"
			mu.Lock()
			records = append(records, req.dnsRecord)
			mu.Unlock()
			close(created)
			if mode == "lost response" {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(recordResult{Success: true, Result: req.dnsRecord})
		case http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/zone-id/dns_records/")
			mu.Lock()
			defer mu.Unlock()
			for i, rec := range records {
				if rec.ID == id {
					records = append(records[:i], records[i+1:]...)
					break
				}
			}
			_ = json.NewEncoder(w).Encode(recordResult{Success: true})
		}
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &http.Client{Transport: localTransport{base: server.Client().Transport, url: endpoint}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanup dnsrecord.Cleanup
	var err error
	done := make(chan struct{})
	go func() {
		cleanup, err = presentChallenge(ctx, client, "token", "zone-id", "_acme-challenge.example.com.", "value", 420)
		close(done)
	}()
	if mode == "lost response" {
		select {
		case <-created:
		case <-time.After(5 * time.Second):
			t.Fatal("create did not reach server")
		}
		cancel()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not stop")
	}
	if mode == "preexisting" {
		if cleanup != nil || err != nil {
			t.Fatalf("preexisting publication = %v, %v", cleanup != nil, err)
		}
		return
	}
	canceled := mode == "lost response" && errors.Is(err, context.Canceled)
	successful := mode == "success" && err == nil
	if cleanup == nil || (!canceled && !successful) {
		t.Fatalf("publication = %v, %v", cleanup != nil, err)
	}
	cancel()
	if mode == "success" {
		mu.Lock()
		records = append(records, dnsRecord{ID: "another-owner", Type: "TXT", Name: "_acme-challenge.example.com", Content: "value"})
		mu.Unlock()
	}
	for range 2 {
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := 1
	if mode == "success" {
		want++
	}
	if len(records) != want || records[0].ID != "wrong-name" {
		t.Fatalf("remaining records = %+v", records)
	}
}

func TestChallengeConfiguration(t *testing.T) {
	t.Setenv("CLOUDFLARE_PROPAGATION_TIMEOUT", "53")
	t.Setenv("CLOUDFLARE_POLLING_INTERVAL", "7")
	t.Setenv("CLOUDFLARE_TTL", "420")
	provider, err := New("token").ChallengeProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	timeout, interval := provider.(challenge.ProviderTimeout).Timeout()
	if timeout != 53*time.Second || interval != 7*time.Second {
		t.Fatalf("timeout = %v, interval = %v", timeout, interval)
	}
	t.Setenv("CLOUDFLARE_TTL", "1")
	if _, err := New("token").ChallengeProvider(context.Background()); err == nil {
		t.Fatal("invalid Cloudflare TTL accepted")
	}
}

func TestFindZonePrefersChildOverCachedParent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := []zone{}
		if r.URL.Query().Get("name") == "acme.example.com" {
			result = append(result, zone{ID: "child", Name: "acme.example.com"})
		}
		_ = json.NewEncoder(w).Encode(zonesResult{Success: true, Result: result})
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &http.Client{Transport: localTransport{base: server.Client().Transport, url: endpoint}}
	p := New("token")
	p.zones.UpdateCopy(func(zones *map[string]string) { (*zones)["example.com"] = "parent" })
	zoneID, err := p.findZoneID(context.Background(), client, "token.acme.example.com")
	if err != nil || zoneID != "child" {
		t.Fatalf("zone = %q, %v", zoneID, err)
	}
}

func TestListZonesUsesSupportedPageSizeAndFollowsPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/client/v4/zones" || query.Get("per_page") != "50" || query.Get("name") != "example.test" {
			t.Errorf("unexpected List Zones request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		page := query.Get("page")
		if page != "1" && page != "2" {
			t.Errorf("unexpected page: %q", page)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(zonesResult{Success: true, Result: []zone{{ID: page}}, Info: resultInfo{TotalPages: 2}})
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	client := &http.Client{Transport: localTransport{base: server.Client().Transport, url: endpoint}}
	zones, err := listZones(t.Context(), client, "test-token", "example.test")
	if err != nil || len(zones) != 2 {
		t.Fatalf("zone pagination returned %v, %v", zones, err)
	}
	if zones[0].ID != "1" || zones[1].ID != "2" {
		t.Fatalf("zone pages returned %v", zones)
	}
}
