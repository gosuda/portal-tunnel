package vultr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vultr/govultr/v3"
)

func TestPreferredDSRecordPrefersSHA256(t *testing.T) {
	t.Parallel()

	got := preferredDSRecord([]string{
		"example.com IN DNSKEY 257 3 13 abc",
		"example.com IN DS 27933 13 1 2d9ac457e5c11a104e25d971d0a6254562bddde7",
		"example.com IN DS 27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9",
	})
	if got != "27933 13 2 8858e7b0dfb881280ce2ca1e0eafcd93d5b53687c21da284d4f8799ba82208a9" {
		t.Fatalf("preferredDSRecord() = %q", got)
	}
}

type ensureRecordVultrFake struct {
	t       *testing.T
	mu      sync.Mutex
	records map[string]govultr.DomainRecord
}

func newEnsureRecordVultrFake(t *testing.T, recordType, data string) *ensureRecordVultrFake {
	t.Helper()
	return &ensureRecordVultrFake{
		t: t,
		records: map[string]govultr.DomainRecord{
			"ipv4":  {ID: "ipv4", Name: "relay", Type: "A", Data: "192.0.2.1"},
			"ipv6":  {ID: "ipv6", Name: "relay", Type: "AAAA", Data: "2001:db8::1"},
			"other": {ID: "other", Name: "other", Type: recordType, Data: data},
			"txt":   {ID: "txt", Name: "relay", Type: "TXT", Data: "preserve me"},
		},
	}
}

func (f *ensureRecordVultrFake) serveEnsureRecordVultr(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	const recordsPath = "/v2/domains/example.com/records"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == recordsPath:
		f.listEnsureRecordVultr(w)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
		f.patchEnsureRecordVultr(w, r)
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}
}

func (f *ensureRecordVultrFake) listEnsureRecordVultr(w http.ResponseWriter) {
	listed := make([]govultr.DomainRecord, 0, len(f.records))
	for _, rec := range f.records {
		listed = append(listed, rec)
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"records": listed}); err != nil {
		f.t.Error(err)
	}
}

func (f *ensureRecordVultrFake) patchEnsureRecordVultr(w http.ResponseWriter, r *http.Request) {
	const recordsPath = "/v2/domains/example.com/records"
	id := strings.TrimPrefix(r.URL.Path, recordsPath+"/")
	rec, ok := f.records[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	var update govultr.DomainRecordUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		f.t.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if update.Name != nil {
		rec.Name = *update.Name
	}
	rec.Type, rec.Data = update.Type, update.Data
	f.records[id] = rec
	w.WriteHeader(http.StatusNoContent)
}

func (f *ensureRecordVultrFake) verifyEnsureRecordVultr(recordType, data string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	got := make(map[string]string, len(f.records))
	for _, rec := range f.records {
		got[rec.Type+" "+rec.Name] = rec.Data
	}
	want := map[string]string{
		"A relay":             "192.0.2.1",
		"AAAA relay":          "2001:db8::1",
		recordType + " other": data,
		"TXT relay":           "preserve me",
	}
	want[recordType+" relay"] = data
	if len(f.records) != len(want) || !reflect.DeepEqual(got, want) {
		f.t.Fatalf("records = %#v, want %#v", f.records, want)
	}
}

func TestEnsureRecordPreservesOtherAddressFamily(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		recordType string
		data       string
	}{
		{recordType: "A", data: "192.0.2.2"},
		{recordType: "AAAA", data: "2001:db8::2"},
	} {
		t.Run(tc.recordType, func(t *testing.T) {
			t.Parallel()

			fake := newEnsureRecordVultrFake(t, tc.recordType, tc.data)
			server := httptest.NewServer(http.HandlerFunc(fake.serveEnsureRecordVultr))
			defer server.Close()

			client := govultr.NewClient(server.Client())
			if err := client.SetBaseURL(server.URL); err != nil {
				t.Fatal(err)
			}
			if err := ensureRecord(context.Background(), client, "example.com", "relay.example.com", tc.recordType, tc.data); err != nil {
				t.Fatal(err)
			}
			fake.verifyEnsureRecordVultr(tc.recordType, tc.data)
		})
	}
}

func TestFindZoneMatchesParentCandidate(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/domains" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"domains": []map[string]any{{"domain": "example.com"}},
			"meta":    map[string]any{"total": 1},
		})
	}))
	defer server.Close()

	client := govultr.NewClient(server.Client())
	if err := client.SetBaseURL(server.URL); err != nil {
		t.Fatal(err)
	}
	provider := New("test-key")

	zone, err := provider.findZone(context.Background(), client, "relay.example.com")
	if err != nil || zone != "example.com" {
		t.Fatalf("findZone(relay.example.com) = %q, %v; want example.com", zone, err)
	}
	if _, err := provider.findZone(context.Background(), client, "relay.other.example"); err == nil || !strings.Contains(err.Error(), "no vultr domain found") {
		t.Fatalf("findZone outside every listed domain = %v; want a no-domain refusal", err)
	}
}
