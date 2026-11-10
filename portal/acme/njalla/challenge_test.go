package njalla

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

func TestChallengeLostResponse(t *testing.T)     { testChallengeLifecycle(t, false) }
func TestChallengePreexistingValue(t *testing.T) { testChallengeLifecycle(t, true) }

func testChallengeLifecycle(t *testing.T, preexisting bool) {
	t.Helper()
	var mu sync.Mutex
	records := []record{{ID: "other", Name: "_acme-challenge", Type: "TXT", Content: "value-other"}}
	if preexisting {
		records = append(records, record{ID: "existing", Name: "_acme-challenge", Type: "TXT", Content: "value"})
	}
	created := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params record `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if req.Params.Domain != "example.com" {
			t.Errorf("domain = %q", req.Params.Domain)
		}
		switch req.Method {
		case "list-records":
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"result": recordsResult{Records: records}})
		case "add-record":
			if req.Params.TTL != 420 || req.Params.Content != "value" || req.Params.Name != "_acme-challenge" {
				t.Errorf("unexpected create: %+v", req.Params)
			}
			req.Params.ID = "new"
			mu.Lock()
			records = append(records, req.Params)
			mu.Unlock()
			close(created)
			<-r.Context().Done()
		case "remove-record":
			mu.Lock()
			defer mu.Unlock()
			for i, rec := range records {
				if rec.ID == req.Params.ID {
					records = append(records[:i], records[i+1:]...)
					break
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{}})
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
	}))
	defer server.Close()
	client := &apiClient{token: "test", endpoint: server.URL, httpClient: server.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanup dnsrecord.Cleanup
	var err error
	done := make(chan struct{})
	go func() {
		cleanup, err = presentChallenge(ctx, client, "example.com", "_acme-challenge.example.com.", "value", 420)
		close(done)
	}()
	if !preexisting {
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
	if preexisting {
		if cleanup != nil || err != nil {
			t.Fatalf("preexisting publication = %v, %v", cleanup != nil, err)
		}
	} else {
		if !errors.Is(err, context.Canceled) || cleanup == nil {
			t.Fatalf("canceled publication = %v, %v", cleanup != nil, err)
		}
		for range 2 {
			if err := cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := 1
	if preexisting {
		want++
	}
	if len(records) != want || records[0].ID != "other" {
		t.Fatalf("remaining records = %+v", records)
	}
}

func TestChallengeConfiguration(t *testing.T) {
	t.Setenv("NJALLA_PROPAGATION_TIMEOUT", "53")
	t.Setenv("NJALLA_POLLING_INTERVAL", "7")
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
		var req struct {
			Params record `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Params.Domain != "acme.example.com" {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": apiError{Code: 404, Message: "domain not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": recordsResult{}})
	}))
	defer server.Close()
	client := &apiClient{token: "test", endpoint: server.URL, httpClient: server.Client()}
	p := New("token")
	p.zones.UpdateCopy(func(zones *map[string]string) { (*zones)["example.com"] = "example.com" })
	zone, err := p.findZone(context.Background(), client, "token.acme.example.com")
	if err != nil || zone != "acme.example.com" {
		t.Fatalf("zone = %q, %v", zone, err)
	}
}
