package hetzner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

func TestChallengeCanceledPolling(t *testing.T)  { testChallengeLifecycle(t, "cancel polling") }
func TestChallengePollingBudget(t *testing.T)    { testChallengeLifecycle(t, "polling budget") }
func TestChallengeLostResponse(t *testing.T)     { testChallengeLifecycle(t, "lost response") }
func TestChallengePreexistingValue(t *testing.T) { testChallengeLifecycle(t, "preexisting") }

func testChallengeLifecycle(t *testing.T, mode string) {
	t.Helper()
	var mu sync.Mutex
	records := []map[string]any{{"value": `"value-other"`, "comment": "preserve"}}
	if mode == "preexisting" {
		records = append(records, map[string]any{"value": `"value"`})
	}
	pollStarted := make(chan struct{})
	createStarted := make(chan struct{})
	var pollOnce sync.Once
	cleaning := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/actions":
			mu.Lock()
			cleanup := cleaning
			mu.Unlock()
			pollOnce.Do(func() { close(pollStarted) })
			if !cleanup && mode == "cancel polling" {
				<-r.Context().Done()
				return
			}
			status := "running"
			if cleanup {
				status = "success"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"actions": []map[string]any{{"id": 7, "status": status}}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/example.com/rrsets/_acme-challenge/TXT":
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"rrset": map[string]any{
				"zone": 123, "id": "_acme-challenge/TXT", "name": "_acme-challenge", "type": "TXT", "ttl": 900, "records": records,
			}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actions/add_records"):
			var req struct {
				TTL     int              `json:"ttl"`
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.TTL != 900 || len(req.Records) != 1 || req.Records[0]["value"] != `"value"` {
				t.Errorf("unexpected add records: %+v", req)
			}
			mu.Lock()
			records = append(records, req.Records...)
			mu.Unlock()
			close(createStarted)
			if mode == "lost response" {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"action": map[string]any{"id": 7, "status": "running"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actions/remove_records"):
			var req struct {
				Records []map[string]any `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if len(req.Records) != 1 || req.Records[0]["value"] != `"value"` {
				t.Errorf("unexpected removal: %+v", req)
			}
			mu.Lock()
			for i, rec := range records {
				if rec["value"] == `"value"` {
					records = append(records[:i], records[i+1:]...)
					break
				}
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"action": map[string]any{"id": 8, "status": "success"}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := hcloud.NewClient(hcloud.WithToken("test"), hcloud.WithEndpoint(server.URL), hcloud.WithHTTPClient(server.Client()),
		hcloud.WithPollOpts(hcloud.PollOpts{BackoffFunc: hcloud.ConstantBackoff(time.Millisecond)}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timeout := time.Second
	if mode == "polling budget" {
		timeout = 100 * time.Millisecond
	}
	var cleanup dnsrecord.Cleanup
	var err error
	done := make(chan struct{})
	go func() {
		cleanup, err = presentChallenge(ctx, client, &hcloud.Zone{Name: "example.com"}, "_acme-challenge.example.com.", "value", 420, timeout)
		close(done)
	}()
	var started <-chan struct{}
	switch mode {
	case "cancel polling":
		started = pollStarted
	case "lost response":
		started = createStarted
	}
	if started != nil {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("publication did not reach server")
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
	wantErr := context.Canceled
	if mode == "polling budget" {
		wantErr = context.DeadlineExceeded
	}
	if cleanup == nil || !errors.Is(err, wantErr) {
		t.Fatalf("publication = %v, %v", cleanup != nil, err)
	}
	mu.Lock()
	cleaning = true
	mu.Unlock()
	for range 2 {
		if err := cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 || records[0]["value"] != `"value-other"` || records[0]["comment"] != "preserve" {
		t.Fatalf("remaining records = %+v", records)
	}
}

func TestChallengeConfiguration(t *testing.T) {
	t.Setenv("HETZNER_PROPAGATION_TIMEOUT", "53")
	t.Setenv("HETZNER_POLLING_INTERVAL", "7")
	provider, err := New("token").ChallengeProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	timeout, interval := provider.(challenge.ProviderTimeout).Timeout()
	if timeout != 53*time.Second || interval != 7*time.Second {
		t.Fatalf("timeout = %v, interval = %v", timeout, interval)
	}
}

func TestFindZonePrefersChildOverCachedParent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/zones/acme.example.com" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "not_found", "message": "zone not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"zone": map[string]any{"id": 123, "name": "acme.example.com"}})
	}))
	defer server.Close()
	client := hcloud.NewClient(hcloud.WithToken("test"), hcloud.WithEndpoint(server.URL), hcloud.WithHTTPClient(server.Client()))
	p := New("token")
	p.zones.UpdateCopy(func(zones *map[string]string) { (*zones)["example.com"] = "example.com" })
	zone, err := p.findZone(context.Background(), client, "token.acme.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "acme.example.com" {
		t.Fatalf("zone = %+v", zone)
	}
}
