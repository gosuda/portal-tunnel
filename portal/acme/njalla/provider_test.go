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

type ensureRecordNjallaFake struct {
	t       *testing.T
	mu      sync.Mutex
	records map[recordID]record
}

func newEnsureRecordNjallaFake(t *testing.T, recordType, content string) *ensureRecordNjallaFake {
	t.Helper()
	return &ensureRecordNjallaFake{
		t: t,
		records: map[recordID]record{
			"ipv4":  {ID: "ipv4", Name: "relay", Type: "A", Content: "192.0.2.1"},
			"ipv6":  {ID: "ipv6", Name: "relay", Type: "AAAA", Content: "2001:db8::1"},
			"other": {ID: "other", Name: "other", Type: recordType, Content: content},
			"txt":   {ID: "txt", Name: "relay", Type: "TXT", Content: "preserve me"},
		},
	}
}

func (f *ensureRecordNjallaFake) serveEnsureRecordNjalla(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var request struct {
		Method string `json:"method"`
		Params record `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		f.t.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodPost || request.Params.Domain != "example.com" {
		f.t.Errorf("unexpected request: %s %+v", r.Method, request)
		http.Error(w, "unexpected request", http.StatusBadRequest)
		return
	}
	result, ok := f.applyEnsureRecordNjalla(w, request.Method, request.Params)
	if !ok {
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"result": result}); err != nil {
		f.t.Error(err)
	}
}

func (f *ensureRecordNjallaFake) applyEnsureRecordNjalla(w http.ResponseWriter, method string, params record) (any, bool) {
	switch method {
	case "list-records":
		return f.listEnsureRecordNjalla(), true
	case "remove-record":
		f.removeEnsureRecordNjalla(params.ID)
		return nil, true
	case "add-record":
		return f.addEnsureRecordNjalla(params), true
	default:
		f.t.Errorf("unexpected method %q", method)
		http.Error(w, "unexpected method", http.StatusBadRequest)
		return nil, false
	}
}

func (f *ensureRecordNjallaFake) listEnsureRecordNjalla() recordsResult {
	listed := make([]record, 0, len(f.records))
	for _, rec := range f.records {
		listed = append(listed, rec)
	}
	return recordsResult{Records: listed}
}

func (f *ensureRecordNjallaFake) removeEnsureRecordNjalla(id recordID) {
	delete(f.records, id)
}

func (f *ensureRecordNjallaFake) addEnsureRecordNjalla(params record) record {
	rec := params
	rec.ID = "new"
	f.records[rec.ID] = rec
	return rec
}

func (f *ensureRecordNjallaFake) verifyEnsureRecordNjalla(recordType, content string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	got := make(map[string]string, len(f.records))
	for _, rec := range f.records {
		got[rec.Type+" "+rec.Name] = rec.Content
	}
	want := map[string]string{
		"A relay":             "192.0.2.1",
		"AAAA relay":          "2001:db8::1",
		recordType + " other": content,
		"TXT relay":           "preserve me",
	}
	want[recordType+" relay"] = content
	if len(f.records) != len(want) || !reflect.DeepEqual(got, want) {
		f.t.Fatalf("records = %#v, want %#v", f.records, want)
	}
}

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

			fake := newEnsureRecordNjallaFake(t, tc.recordType, tc.content)
			server := httptest.NewServer(http.HandlerFunc(fake.serveEnsureRecordNjalla))
			defer server.Close()

			client := &apiClient{endpoint: server.URL, httpClient: server.Client()}
			if err := ensureRecord(context.Background(), client, "example.com", "relay.example.com", tc.recordType, tc.content); err != nil {
				t.Fatal(err)
			}
			fake.verifyEnsureRecordNjalla(tc.recordType, tc.content)
		})
	}
}
