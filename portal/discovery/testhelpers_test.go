package discovery

import "time"

// stubRelayPolicy is a minimal relayPolicy for tests in package discovery that
// cannot import portal/discovery/selectors/mols (import cycle). It implements
// the four interface methods with simple non-scoring logic sufficient for
// RelaySet lifecycle and announce tests.
type stubRelayPolicy struct{}

func (s stubRelayPolicy) SelectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, st := range states {
		if !st.Banned {
			out = append(out, st)
		}
	}
	return out
}

func (s stubRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, st := range states {
		if st.Confirmed {
			out = append(out, st)
		}
	}
	return out
}

func (s stubRelayPolicy) SelectPriorityWithTrace(states []RelayState, cs ClientState) ([]string, SelectionTrace) {
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

func (s stubRelayPolicy) SelectMultiHopWithTrace(states []RelayState, cs ClientState) ([]string, SelectionTrace) {
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
		if !st.Banned && st.HasObservedDescriptor() && st.Descriptor.HasOverlayPeer() {
			urls = append(urls, st.Descriptor.APIHTTPSAddr)
		}
	}
	trace.OutputURLs = urls
	return urls, trace
}

func newTestRelaySet(bootstrapRelayURLs []string) *RelaySet {
	return NewRelaySet(bootstrapRelayURLs, stubRelayPolicy{})
}
