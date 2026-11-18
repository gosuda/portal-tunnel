package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// Every healthy source in the bounded sample remains observable even when
// directory discovery and other admitted reads consume the shared slots.
func TestFederatedCommentsIncludeEightSlowSources(t *testing.T) {
	for _, cold := range []bool{false, true} {
		t.Run(fmt.Sprintf("cold=%v", cold), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now().UTC()
				lookup := NewServiceLookup(NewRelaySet(nil))
				for i := range serviceRelayLimit {
					root := fmt.Sprintf("relay-%02d.example", i)
					relay := "https://" + root
					lookup.relays.relays[relay] = relayState{
						Descriptor: types.RelayDescriptor{APIHTTPSAddr: relay, ExpiresAt: now.Add(time.Minute)},
						Trust:      relayVerified, LastSeenAt: now,
					}
					if !cold {
						hostname, err := namespace.LocalTLSHostname("blog", serviceTestAddress, root)
						if err != nil {
							t.Fatal(err)
						}
						lookup.cache[relay] = serviceObservation{
							leases: []types.Lease{{Name: "blog", Address: serviceTestAddress,
								Hostname: "blog." + root, CanonicalHostname: hostname, ExpiresAt: now.Add(time.Minute)}},
							at: now, until: now.Add(serviceCacheTTL),
						}
					}
				}
				lookup.client.Transport = commentRoundTrip(func(r *http.Request) (*http.Response, error) {
					var payload any
					delay := 1800 * time.Millisecond
					switch r.URL.Path {
					case types.PathState:
						delay = 500 * time.Millisecond
						hostname, err := namespace.LocalTLSHostname("blog", serviceTestAddress, r.URL.Hostname())
						if err != nil {
							return nil, err
						}
						payload = types.PublicStateResponse{Leases: []types.Lease{{Name: "blog", Address: serviceTestAddress,
							Hostname: "blog." + r.URL.Hostname(), CanonicalHostname: hostname, ExpiresAt: now.Add(time.Minute)}}}
					case types.PathComments:
						payload = types.ServiceCommentsResponse{Comments: []types.ObservedServiceComment{{
							ID: "comment", Text: "slow source", CreatedAt: now,
						}}}
					default:
						return nil, fmt.Errorf("unexpected source path: %s", r.URL.Path)
					}
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-timer.C:
					}
					body, err := json.Marshal(types.APIEnvelope[any]{OK: true, Data: payload})
					if err != nil {
						return nil, err
					}
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}, nil
				})
				var workers sync.WaitGroup
				for range commentLookupLimit {
					workers.Go(func() {
						response, err := lookup.Comments(t.Context(), "https://local.example", serviceTestAddress, "blog")
						if err != nil {
							t.Error(err)
							return
						}
						origins := make(map[string]bool)
						for _, row := range response.Comments {
							origins[row.RelayURL] = true
						}
						if response.Partial || response.RelaysChecked != serviceRelayLimit || len(origins) != serviceRelayLimit {
							t.Errorf("healthy sources lost from bounded sample: %+v", response)
						}
					})
				}
				workers.Wait()
			})
		})
	}
}

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
		hostname, err := namespace.LocalTLSHostname("blog", owner, root)
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
		expected, err := namespace.LocalTLSHostname("blog", serviceTestAddress, root)
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

	result, err := lookup.Comments(t.Context(), self, serviceTestAddress, "blog")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.RelaysChecked != 2 || result.RelaysSkipped != 1 || len(result.Comments) != 2 {
		t.Fatalf("unexpected comment coverage: %+v", result)
	}
	if result.Comments[0].RelayURL != "https://a.example" || result.Comments[1].RelayURL != "https://b.example" ||
		result.Comments[0].ID != "same" || result.Comments[1].ID != "same" {
		t.Fatalf("comment IDs or provenance were collapsed: %+v", result.Comments)
	}

	// One call returns the complete bounded sample; no continuation exists.
	count = commentSourceLimit
	sample, err := lookup.Comments(t.Context(), self, serviceTestAddress, "blog")
	if err != nil {
		t.Fatal(err)
	}
	if len(sample.Comments) != 2*commentSourceLimit {
		t.Fatalf("bounded sample lost rows: %d", len(sample.Comments))
	}

	// Remove a source that contributed rows to the previous sample. The next
	// sample must drop those rows and keep each remaining row only once.
	removed := "https://b.example"
	delete(lookup.cache, removed)
	relaySet.relays[removed] = relayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: removed, ExpiresAt: now.Add(time.Minute)}, Trust: relayVerified, LastSeenAt: now, Banned: true}
	shrunk, err := lookup.Comments(t.Context(), self, serviceTestAddress, "blog")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, row := range shrunk.Comments {
		key := row.RelayURL + "\x00" + row.ID
		if seen[key] || row.RelayURL == removed {
			t.Fatalf("sample repeated a row or kept a removed source: %+v", row)
		}
		seen[key] = true
	}
	if len(shrunk.Comments) != commentSourceLimit || shrunk.RelaysChecked != 1 {
		t.Fatalf("source removal changed the remaining sample: %+v", shrunk)
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

func TestFederatedCommentsDiscoveredForAliasOnlyService(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now().UTC()
		relaySet := NewRelaySet(nil)
		lookup := NewServiceLookup(relaySet)
		self := "https://self.example"
		remote := "https://remote.example"

		relaySet.relays[remote] = relayState{
			Descriptor: types.RelayDescriptor{APIHTTPSAddr: remote, ExpiresAt: now.Add(time.Minute)},
			Trust:      relayVerified,
			LastSeenAt: now,
		}

		lookup.cache[remote] = serviceObservation{
			leases: []types.Lease{{
				Name:              "blog",
				Address:           serviceTestAddress,
				Hostname:          "blog.remote.example",
				CanonicalHostname: "",
				ExpiresAt:         now.Add(time.Minute),
			}},
			at:    now,
			until: now.Add(serviceCacheTTL),
		}

		calledWithHost := ""
		lookup.client.Transport = commentRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == types.PathComments {
				calledWithHost = r.URL.Query().Get("hostname")
				payload := types.ServiceCommentsResponse{
					Comments: []types.ObservedServiceComment{{
						ID:        "c1",
						Text:      "alias comment",
						CreatedAt: now,
					}},
				}
				data, _ := json.Marshal(types.APIEnvelope[any]{Data: payload, OK: true})
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(string(data))),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})

		resp, err := lookup.Comments(t.Context(), self, serviceTestAddress, "blog")
		if err != nil {
			t.Fatal(err)
		}
		if calledWithHost != "blog.remote.example" {
			t.Fatalf("expected comments lookup with host blog.remote.example, got: %q", calledWithHost)
		}
		if len(resp.Comments) != 1 || resp.Comments[0].Text != "alias comment" {
			t.Fatalf("expected alias comment returned, got: %+v", resp.Comments)
		}
	})
}
