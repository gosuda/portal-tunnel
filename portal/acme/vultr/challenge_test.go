package vultr

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
	"github.com/vultr/govultr/v3"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

func TestChallengeLostResponse(t *testing.T)      { testChallengeLifecycle(t, "lost response") }
func TestChallengeSuccessfulCleanup(t *testing.T) { testChallengeLifecycle(t, "success") }
func TestChallengePreexistingValue(t *testing.T)  { testChallengeLifecycle(t, "preexisting") }

func testChallengeLifecycle(t *testing.T, mode string) {
	t.Helper()
	var mu sync.Mutex
	records := []govultr.DomainRecord{{ID: "other", Name: "_acme-challenge", Type: "TXT", Data: "value-other"}}
	if mode == "preexisting" {
		records = append(records, govultr.DomainRecord{ID: "existing", Name: "_acme-challenge", Type: "TXT", Data: `"value"`})
	}
	created := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v2/domains/example.com/records") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"records": records, "meta": map[string]any{"total": len(records)}})
		case http.MethodPost:
			var req govultr.DomainRecordCreateReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.TTL != 420 || req.Data != `"value"` || req.Name != "_acme-challenge" {
				t.Errorf("unexpected create: %+v", req)
			}
			rec := govultr.DomainRecord{ID: "new", Name: req.Name, Type: req.Type, Data: req.Data}
			mu.Lock()
			records = append(records, rec)
			mu.Unlock()
			close(created)
			if mode == "lost response" {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"record": rec})
		case http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/v2/domains/example.com/records/")
			mu.Lock()
			defer mu.Unlock()
			for i, rec := range records {
				if rec.ID == id {
					records = append(records[:i], records[i+1:]...)
					break
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()
	client := govultr.NewClient(server.Client())
	if err := client.SetBaseURL(server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanup dnsrecord.Cleanup
	var err error
	done := make(chan struct{})
	go func() {
		cleanup, err = presentChallenge(ctx, client, "example.com", "_acme-challenge.example.com.", "value", 420)
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
		records = append(records, govultr.DomainRecord{ID: "another-owner", Name: "_acme-challenge", Type: "TXT", Data: "value"})
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
	if len(records) != want || records[0].ID != "other" {
		t.Fatalf("remaining records = %+v", records)
	}
}

func TestChallengeConfiguration(t *testing.T) {
	t.Setenv("VULTR_PROPAGATION_TIMEOUT", "53")
	t.Setenv("VULTR_POLLING_INTERVAL", "7")
	provider, err := New("token").ChallengeProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	timeout, interval := provider.(challenge.ProviderTimeout).Timeout()
	if timeout != 53*time.Second || interval != 7*time.Second {
		t.Fatalf("timeout = %v, interval = %v", timeout, interval)
	}
}

func TestFindZonePrefersChildOnLaterPageOverCachedParent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, next := "example.com", "next-page"
		if r.URL.Query().Get("cursor") == next {
			name, next = "acme.example.com", ""
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"domains": []map[string]any{{"domain": name}},
			"meta":    map[string]any{"total": 2, "links": map[string]any{"next": next}},
		})
	}))
	defer server.Close()
	client := govultr.NewClient(server.Client())
	if err := client.SetBaseURL(server.URL); err != nil {
		t.Fatal(err)
	}
	p := New("token")
	p.zones.UpdateCopy(func(zones *map[string]string) { (*zones)["example.com"] = "example.com" })
	zone, err := p.findZone(context.Background(), client, "token.acme.example.com")
	if err != nil || zone != "acme.example.com" {
		t.Fatalf("zone = %q, %v", zone, err)
	}
}
