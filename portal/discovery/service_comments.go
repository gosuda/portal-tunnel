package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// Comment reads have their own admission and outbound budget so comment
	// traffic cannot take the service directory's capacity.
	commentLookupLimit = 2
	commentConcurrency = 2
	commentSourceLimit = 20
	commentPageSize    = 30
	commentBodyLimit   = 1 << 20
	commentDecodeLimit = 100
	commentIDLimit     = 128
)

type commentSource struct {
	hostname  string
	expiresAt time.Time
}

// Comments fetches anonymous public comments only from currently eligible
// sources observed to host this exact identity. It neither stores nor writes them.
func (s *ServiceLookup) Comments(ctx context.Context, self, address, name string, offset int) (types.ServiceCommentsResponse, error) {
	select {
	case s.commentLookups <- struct{}{}:
		defer func() { <-s.commentLookups }()
	default:
		return types.ServiceCommentsResponse{}, errServiceLookupBusy
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	response := types.ServiceCommentsResponse{Comments: []types.ObservedServiceComment{}}
	if address == "" || offset < 0 || offset >= types.ServiceCommentMaxOffset {
		return response, nil
	}
	sources := make(map[string]commentSource)
	lookup := s.lookup(ctx, self, nil, address, &name, s.commentSlots, sources)
	response.RelaysSkipped = lookup.RelaysSkipped
	type result struct {
		relay   string
		rows    []types.ObservedServiceComment
		partial bool
		err     error
	}
	// Cached directory coverage may be larger than one refresh window. Keep
	// actual comment reads bounded, and prefer the freshest observations.
	now := time.Now().UTC()
	targets := make([]string, 0, len(sources))
	for relay, source := range sources {
		if source.hostname == "" || !source.expiresAt.After(now) {
			response.RelaysSkipped++
			continue
		}
		targets = append(targets, relay)
	}
	slices.SortFunc(targets, func(a, b string) int {
		if order := sources[b].expiresAt.Compare(sources[a].expiresAt); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	if len(targets) > serviceRelayLimit {
		response.RelaysSkipped += len(targets) - serviceRelayLimit
		targets = targets[:serviceRelayLimit]
	}
	results := make(chan result, len(targets))
	var workers sync.WaitGroup
	for _, relay := range targets {
		source := sources[relay]
		workers.Go(func() {
			rows, partial, err := s.fetchServiceComments(ctx, relay, source.hostname)
			results <- result{relay: relay, rows: rows, partial: partial, err: err}
		})
	}
	workers.Wait()
	close(results)

	now = time.Now().UTC()
	eligible := s.relays.serviceTargets(now)
	var merged []types.ObservedServiceComment
	for item := range results {
		if item.err != nil || !slices.Contains(eligible, item.relay) || !sources[item.relay].expiresAt.After(now) {
			response.RelaysSkipped++
			continue
		}
		response.RelaysChecked++
		response.Partial = response.Partial || item.partial
		merged = append(merged, item.rows...)
	}
	response.Partial = response.Partial || lookup.Partial || response.RelaysSkipped > 0
	sortServiceComments(merged)
	if offset < len(merged) {
		end := min(offset+commentPageSize, len(merged))
		response.Comments = merged[offset:end]
		if end < len(merged) && end < types.ServiceCommentMaxOffset {
			response.NextOffset = &end
		}
	}
	return response, nil
}

func (s *ServiceLookup) fetchServiceComments(ctx context.Context, relay, hostname string) ([]types.ObservedServiceComment, bool, error) {
	if err := requirePublicRelayURL(relay); err != nil {
		return nil, false, err
	}
	base, err := url.Parse(relay)
	if err != nil {
		return nil, false, err
	}
	target := utils.ResolveAPIURL(base, types.PathComments)
	target.RawQuery = url.Values{"hostname": {hostname}}.Encode()
	select {
	case s.commentSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	defer func() { <-s.commentSlots }()
	ctx, cancel := context.WithTimeout(ctx, serviceRelayTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err := readServiceResponse(resp, commentBodyLimit)
	if err != nil {
		return nil, false, err
	}
	var envelope types.APIEnvelope[struct {
		Comments []json.RawMessage `json:"comments"`
	}]
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, err
	}
	if !envelope.OK || envelope.Data.Comments == nil || len(envelope.Data.Comments) > commentDecodeLimit {
		return nil, false, errors.New("service comments response rejected")
	}
	rows, partial := observedServiceComments(relay, envelope.Data.Comments, time.Now().UTC())
	return rows, partial, nil
}

func sortServiceComments(rows []types.ObservedServiceComment) {
	slices.SortFunc(rows, func(a, b types.ObservedServiceComment) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		if a.RelayURL != b.RelayURL {
			return strings.Compare(a.RelayURL, b.RelayURL)
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func observedServiceComments(relay string, raws []json.RawMessage, now time.Time) ([]types.ObservedServiceComment, bool) {
	rows := make([]types.ObservedServiceComment, 0, len(raws))
	seen := make(map[string]int, len(raws))
	partial := false
	for _, raw := range raws {
		var row types.ObservedServiceComment
		if err := json.Unmarshal(raw, &row); err != nil || row.ID == "" || len(row.ID) > commentIDLimit ||
			strings.TrimSpace(row.ID) != row.ID || row.CreatedAt.IsZero() || row.CreatedAt.After(now.Add(5*time.Minute)) ||
			(!row.Deleted && (strings.TrimSpace(row.Text) == "" || utf8.RuneCountInString(row.Text) > types.CommentMaxLength)) {
			partial = true
			continue
		}
		row.RelayURL = relay
		if row.Deleted {
			row.Text = ""
		}
		if index, found := seen[row.ID]; found {
			partial = true
			// A tombstone wins within the same response. Never resurrect its text.
			if row.Deleted {
				rows[index] = row
			}
			continue
		}
		seen[row.ID] = len(rows)
		rows = append(rows, row)
	}
	sortServiceComments(rows)
	if len(rows) > commentSourceLimit {
		return rows[:commentSourceLimit], true
	}
	return rows, partial
}
