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

// Registrars reject SHA-1 DS records; the SHA-256 digest must be preferred
// whenever the zone publishes both.
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

// Changing one address family must preserve the other family and unrelated records.
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

			var mu sync.Mutex
			records := map[string]govultr.DomainRecord{
				"ipv4":  {ID: "ipv4", Name: "relay", Type: "A", Data: "192.0.2.1"},
				"ipv6":  {ID: "ipv6", Name: "relay", Type: "AAAA", Data: "2001:db8::1"},
				"other": {ID: "other", Name: "other", Type: tc.recordType, Data: tc.data},
				"txt":   {ID: "txt", Name: "relay", Type: "TXT", Data: "preserve me"},
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()

				const recordsPath = "/v2/domains/example.com/records"
				switch {
				case r.Method == http.MethodGet && r.URL.Path == recordsPath:
					listed := make([]govultr.DomainRecord, 0, len(records))
					for _, rec := range records {
						listed = append(listed, rec)
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"records": listed}); err != nil {
						t.Error(err)
					}
				case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
					id := strings.TrimPrefix(r.URL.Path, recordsPath+"/")
					rec, ok := records[id]
					if !ok {
						http.NotFound(w, r)
						return
					}
					var update govultr.DomainRecordUpdateReq
					if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
						t.Error(err)
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					if update.Name != nil {
						rec.Name = *update.Name
					}
					rec.Type, rec.Data = update.Type, update.Data
					records[id] = rec
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected request", http.StatusBadRequest)
				}
			}))
			defer server.Close()

			client := govultr.NewClient(server.Client())
			if err := client.SetBaseURL(server.URL); err != nil {
				t.Fatal(err)
			}
			if err := ensureRecord(context.Background(), client, "example.com", "relay.example.com", tc.recordType, tc.data); err != nil {
				t.Fatal(err)
			}

			mu.Lock()
			defer mu.Unlock()
			got := make(map[string]string, len(records))
			for _, rec := range records {
				got[rec.Type+" "+rec.Name] = rec.Data
			}
			want := map[string]string{
				"A relay":                "192.0.2.1",
				"AAAA relay":             "2001:db8::1",
				tc.recordType + " other": tc.data,
				"TXT relay":              "preserve me",
			}
			want[tc.recordType+" relay"] = tc.data
			if len(records) != len(want) || !reflect.DeepEqual(got, want) {
				t.Fatalf("records = %#v, want %#v", records, want)
			}
		})
	}
}
