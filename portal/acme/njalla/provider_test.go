package njalla

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

// The njalla API returns record ids as either a JSON string or a JSON number;
// both forms must keep decoding.
func TestRecordIDUnmarshal(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{`{"id":"123"}`, `{"id":123}`} {
		var record record
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", raw, err)
		}
		if record.ID.String() != "123" {
			t.Fatalf("record id = %q, want 123", record.ID.String())
		}
	}
}

// Changing one address family must preserve the other family and unrelated records.
func TestEnsureRecordPreservesOtherAddressFamily(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		recordType string
		content    string
	}{
		{recordType: "A", content: "192.0.2.2"},
		{recordType: "AAAA", content: "2001:db8::2"},
	} {
		t.Run(tc.recordType, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			records := map[recordID]record{
				"ipv4":  {ID: "ipv4", Name: "relay", Type: "A", Content: "192.0.2.1"},
				"ipv6":  {ID: "ipv6", Name: "relay", Type: "AAAA", Content: "2001:db8::1"},
				"other": {ID: "other", Name: "other", Type: tc.recordType, Content: tc.content},
				"txt":   {ID: "txt", Name: "relay", Type: "TXT", Content: "preserve me"},
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()

				var request struct {
					Method string `json:"method"`
					Params record `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if r.Method != http.MethodPost || request.Params.Domain != "example.com" {
					t.Errorf("unexpected request: %s %+v", r.Method, request)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				var result any
				switch request.Method {
				case "list-records":
					listed := make([]record, 0, len(records))
					for _, rec := range records {
						listed = append(listed, rec)
					}
					result = recordsResult{Records: listed}
				case "remove-record":
					delete(records, request.Params.ID)
				case "add-record":
					rec := request.Params
					rec.ID = "new"
					records[rec.ID] = rec
					result = rec
				default:
					t.Errorf("unexpected method %q", request.Method)
					http.Error(w, "unexpected method", http.StatusBadRequest)
					return
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"result": result}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()

			client := &apiClient{endpoint: server.URL, httpClient: server.Client()}
			if err := ensureRecord(context.Background(), client, "example.com", "relay.example.com", tc.recordType, tc.content); err != nil {
				t.Fatal(err)
			}

			mu.Lock()
			defer mu.Unlock()
			got := make(map[string]string, len(records))
			for _, rec := range records {
				got[rec.Type+" "+rec.Name] = rec.Content
			}
			want := map[string]string{
				"A relay":                "192.0.2.1",
				"AAAA relay":             "2001:db8::1",
				tc.recordType + " other": tc.content,
				"TXT relay":              "preserve me",
			}
			want[tc.recordType+" relay"] = tc.content
			if len(records) != len(want) || !reflect.DeepEqual(got, want) {
				t.Fatalf("records = %#v, want %#v", records, want)
			}
		})
	}
}
