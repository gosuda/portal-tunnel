package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type commentRoundTrip func(*http.Request) (*http.Response, error)

func (f commentRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// INV: only a matching relay's public identity endpoint contributes comments;
// a failed origin and repeated IDs on other origins cannot erase its comments.
func TestFederatedCommentsPreserveOriginsAndPartialFailures(t *testing.T) {
	const self = "https://local.example"
	now := time.Now().UTC()
	relaySet := NewRelaySet(nil)
	lookup := NewServiceLookup(relaySet)
	for _, label := range []string{"a", "b", "failed", "different"} {
		root := label + ".example"
		relay := "https://" + root
		relaySet.relays[relay] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now}
		owner := serviceTestAddress
		if label == "different" {
			owner = "0x2222222222222222222222222222222222222222"
		}
		hostname, err := namespace.LegacyHostname("blog", owner, root)
		if err != nil {
			t.Fatal(err)
		}
		lookup.cache[relay] = serviceObservation{
			leases: []types.Lease{{Name: "blog", Address: owner, CanonicalHostname: hostname, Hostname: "blog." + root, ExpiresAt: now.Add(time.Minute)}},
			at:     now, until: now.Add(serviceCacheTTL),
		}
	}

	count := 1
	lookup.client.Transport = commentRoundTrip(func(r *http.Request) (*http.Response, error) {
		root := r.URL.Hostname()
		expected, err := namespace.LegacyHostname("blog", serviceTestAddress, root)
		if err != nil {
			return nil, err
		}
		if r.Method != http.MethodGet || r.URL.Path != types.PathComments || r.URL.Query().Get("hostname") != expected ||
			r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || root == "different.example" {
			t.Errorf("unexpected comments source or request metadata: %s %s", r.Method, r.URL)
			return nil, errors.New("unexpected lookup")
		}
		if root == "failed.example" {
			return nil, errors.New("source offline")
		}
		rows := make([]types.ObservedServiceComment, count)
		for i := range count {
			id := "same"
			if i > 0 {
				id = fmt.Sprintf("comment-%02d", i)
			}
			rows[i] = types.ObservedServiceComment{ID: id, Text: "public comment", CreatedAt: now.Add(-time.Duration(i) * time.Second)}
		}
		body, err := json.Marshal(types.APIEnvelope[types.ServiceCommentsResponse]{
			OK: true, Data: types.ServiceCommentsResponse{Comments: rows},
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}, nil
	})

	result := lookup.Comments(t.Context(), self, serviceTestAddress, "blog", 0)
	if !result.Partial || result.RelaysChecked != 2 || result.RelaysSkipped != 1 || len(result.Comments) != 2 {
		t.Fatalf("unexpected comment coverage: %+v", result)
	}
	if result.Comments[0].RelayURL != "https://a.example" || result.Comments[1].RelayURL != "https://b.example" ||
		result.Comments[0].ID != "same" || result.Comments[1].ID != "same" {
		t.Fatalf("comment IDs or provenance were collapsed: %+v", result.Comments)
	}

	count = commentSourceLimit
	page := lookup.Comments(t.Context(), self, serviceTestAddress, "blog", 0)
	if len(page.Comments) != commentPageSize || page.NextOffset == nil || *page.NextOffset != commentPageSize {
		t.Fatalf("invalid first-page size or continuation: %d rows; next=%v", len(page.Comments), page.NextOffset)
	}
	next := lookup.Comments(t.Context(), self, serviceTestAddress, "blog", *page.NextOffset)
	if len(next.Comments) != 2*commentSourceLimit-commentPageSize || next.NextOffset != nil {
		t.Fatalf("invalid second-page size or continuation: %d rows; next=%v", len(next.Comments), next.NextOffset)
	}
}

func TestObservedCommentsLimitAndPreserveDeletion(t *testing.T) {
	now := time.Now().UTC()
	var rows []json.RawMessage
	for i := range commentSourceLimit + 2 {
		rows = append(rows, fmt.Appendf(nil,
			`{"id":%q,"text":"published text","created_at":%q}`,
			fmt.Sprintf("comment-%02d", i), now.Add(-time.Duration(i)*time.Second).Format(time.RFC3339Nano)))
	}
	rows = append(rows,
		fmt.Appendf(nil, `{"id":"comment-00","text":"must not reappear","created_at":%q,"deleted":true,"relay_url":"https://other.example"}`, now.Format(time.RFC3339Nano)),
		fmt.Appendf(nil, `{"id":"unusable","text":"not a real time","created_at":%q}`, now.Add(time.Hour).Format(time.RFC3339Nano)),
	)
	comments, partial := observedServiceComments("https://relay.example", rows, now)
	if !partial || len(comments) != commentSourceLimit || comments[0].ID != "comment-00" || !comments[0].Deleted ||
		comments[0].Text != "" || comments[0].RelayURL != "https://relay.example" {
		t.Fatalf("inconsistent bounded public observations: %+v", comments)
	}
}
