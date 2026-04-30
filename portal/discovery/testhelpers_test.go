package discovery

import (
	"context"
	"time"
)

// stubSelector is a minimal Selector for tests in package discovery that
// cannot import portal/discovery/selectors/mols (import cycle). It implements
// the Selector interface with simple non-scoring logic sufficient for
// RelaySet lifecycle and announce tests.
type stubSelector struct{}

func (s stubSelector) Name() string { return "stub" }

func (s stubSelector) SelectPriority(_ context.Context, states []RelayState, cs ClientState) ([]string, SelectionTrace) {
	now := time.Now().UTC()
	trace := SelectionTrace{
		Mode:      "priority",
		PoolTotal: len(states),
		Reasons:   make(map[string]string),
	}
	var urls []string
	for _, st := range states {
		if st.Banned {
			continue
		}
		url := st.Descriptor.APIHTTPSAddr
		if st.IsSuppressedActive(now) {
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "suppressed"
			continue
		}
		urls = append(urls, url)
	}
	trace.OutputURLs = urls
	return urls, trace
}

func (s stubSelector) SelectMultiHop(_ context.Context, states []RelayState, cs ClientState) ([]string, SelectionTrace) {
	trace := SelectionTrace{
		Mode:      "multihop",
		PoolTotal: len(states),
		Reasons:   make(map[string]string),
	}
	if cs.MultiHopDepth <= 1 {
		return nil, trace
	}
	var urls []string
	for _, st := range states {
		if len(urls) >= cs.MultiHopDepth {
			break
		}
		if !st.Banned && st.HasObservedDescriptor() && st.Descriptor.HasOverlayPeer() {
			urls = append(urls, st.Descriptor.APIHTTPSAddr)
		}
	}
	trace.OutputURLs = urls
	return urls, trace
}

func newTestRelaySet(bootstrapRelayURLs []string) *RelaySet {
	return NewRelaySet(bootstrapRelayURLs, stubSelector{})
}
