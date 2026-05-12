package policy

import (
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/mols"
	"github.com/gosuda/portal-tunnel/v2/portal/telemetry"
)

// MOLSRelayPolicy implements discovery.RelayPolicy using the mols.Engine for
// deterministic ranking.  It embeds discovery.SimpleRelayPolicy so that all
// state-machine transforms (OnActiveConfirmed, OnDiscoveryFailure, etc.) are
// reused without duplication; only the selection methods are overridden.
type MOLSRelayPolicy struct {
	discovery.SimpleRelayPolicy
	engine *mols.Engine
}

// NewMOLSRelayPolicy creates a policy backed by a MOLS engine.  If cfg is the
// zero value, DefaultConfig is used.  If strategy is nil,
// DefaultAdaptiveStrategy is used.
func NewMOLSRelayPolicy(cfg mols.Config, strategy mols.AdaptiveStrategy) *MOLSRelayPolicy {
	if cfg.Order == 0 {
		cfg = mols.DefaultConfig()
	}
	return &MOLSRelayPolicy{
		SimpleRelayPolicy: discovery.SimpleRelayPolicy{},
		engine:            mols.NewEngine(cfg, strategy),
	}
}

func (p MOLSRelayPolicy) SelectPriority(states []discovery.RelayState, cs discovery.ClientState) []string {
	out, _ := p.SelectPriorityWithTrace(states, cs)
	return out
}

func (p MOLSRelayPolicy) SelectPriorityWithTrace(states []discovery.RelayState, cs discovery.ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := telemetry.SelectionTrace{
		Timestamp:  start,
		ClientHash: mols.HashToGF64(cs.LocalAddress),
		Mode:       "priority",
		PoolTotal:  len(states),
		Reasons:    make(map[string]string),
	}

	for _, state := range states {
		if state.Banned {
			url := state.Descriptor.APIHTTPSAddr
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "banned"
		}
	}

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	explicit := make([]string, 0)
	autoPool := make([]discovery.RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(cs.ExplicitRelayURLs, relayURL) {
			if state.HasObservedDescriptor() && state.Descriptor.ExpiresAt.After(now) {
				if cs.RequireUDP && !state.Descriptor.SupportsUDP {
					trace.Suppressed = append(trace.Suppressed, relayURL)
					trace.Reasons[relayURL] = "require_udp"
					continue
				}
				if cs.RequireTCP && !state.Descriptor.SupportsTCP {
					trace.Suppressed = append(trace.Suppressed, relayURL)
					trace.Reasons[relayURL] = "require_tcp"
					continue
				}
			}
			explicit = append(explicit, relayURL)
			continue
		}
		if state.HasObservedDescriptor() {
			if !state.Descriptor.ExpiresAt.After(now) {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "expired"
				continue
			}
			if cs.RequireUDP && !state.Descriptor.SupportsUDP {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "require_udp"
				continue
			}
			if cs.RequireTCP && !state.Descriptor.SupportsTCP {
				trace.Suppressed = append(trace.Suppressed, relayURL)
				trace.Reasons[relayURL] = "require_tcp"
				continue
			}
		}
		if !state.SuppressActiveUntil().IsZero() && state.SuppressActiveUntil().After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "suppressed"
			continue
		}
		autoPool = append(autoPool, state)
	}

	res := p.rankAutoPool(autoPool, cs.LocalAddress)
	trace.AvgRTT = res.AvgRTT
	trace.CV = res.CV
	trace.Congested = res.Congested
	trace.NonLinear = res.NonLinear
	trace.M1, trace.M2 = res.M1, res.M2
	trace.PoolEligible = len(autoPool)
	trace.PoolFallback = len(res.Demoted)

	ingressIdx := mols.HashToGF64(cs.LocalAddress)
	demotedSet := make(map[string]bool, len(res.Demoted))
	for _, id := range res.Demoted {
		demotedSet[id] = true
	}

	for _, state := range autoPool {
		candidateIdx := mols.HashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if res.Congested {
			score = mols.CongestionScore(ingressIdx, candidateIdx, res.M1, res.M2, res.Order)
		} else {
			score = mols.Score(ingressIdx, candidateIdx, res.M1, res.M2, res.Order)
		}
		trace.Ranked = append(trace.Ranked, telemetry.TraceEntry{
			URL:       state.Descriptor.APIHTTPSAddr,
			Score:     score,
			Confirmed: state.Confirmed,
			RTT:       state.DiscoveryRTT,
			Demoted:   demotedSet[state.Descriptor.APIHTTPSAddr],
		})
	}

	autoURLs := make([]string, 0, len(res.Ordered))
	for _, c := range res.Ordered {
		autoURLs = append(autoURLs, c.ID)
	}

	maxActiveRelays := cs.MaxActiveRelays
	if maxActiveRelays <= 0 {
		maxActiveRelays = p.engine.Config().MaxActiveRelays
	}
	if len(autoURLs) > maxActiveRelays {
		autoURLs = autoURLs[:maxActiveRelays]
	}
	result := append(explicit, autoURLs...)
	trace.OutputURLs = result
	trace.SelectionTook = time.Since(start)
	return result, trace
}

func (p MOLSRelayPolicy) SelectMultiHop(states []discovery.RelayState, cs discovery.ClientState) []string {
	out, _ := p.SelectMultiHopWithTrace(states, cs)
	return out
}

func (p MOLSRelayPolicy) SelectMultiHopWithTrace(states []discovery.RelayState, cs discovery.ClientState) ([]string, telemetry.SelectionTrace) {
	start := time.Now()
	now := start.UTC()

	trace := telemetry.SelectionTrace{
		Timestamp:  start,
		ClientHash: mols.HashToGF64(cs.LocalAddress),
		Mode:       "multihop",
		PoolTotal:  len(states),
		Reasons:    make(map[string]string),
	}

	if cs.MultiHopDepth <= 1 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	for _, state := range states {
		if state.Banned {
			url := state.Descriptor.APIHTTPSAddr
			trace.Suppressed = append(trace.Suppressed, url)
			trace.Reasons[url] = "banned"
		}
	}

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		trace.SelectionTook = time.Since(start)
		return nil, trace
	}

	autoPool := make([]discovery.RelayState, 0, len(selected))
	for _, state := range selected {
		relayURL := state.Descriptor.APIHTTPSAddr
		if cs.RequireUDP && state.HasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_udp"
			continue
		}
		if cs.RequireTCP && state.HasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "require_tcp"
			continue
		}
		if !state.HasObservedDescriptor() {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "no_descriptor"
			continue
		}
		if !state.Descriptor.ExpiresAt.After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "expired"
			continue
		}
		if !state.Descriptor.HasOverlayPeer() {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "no_overlay_peer"
			continue
		}
		if !state.SuppressActiveUntil().IsZero() && state.SuppressActiveUntil().After(now) {
			trace.Suppressed = append(trace.Suppressed, relayURL)
			trace.Reasons[relayURL] = "suppressed"
			continue
		}
		autoPool = append(autoPool, state)
	}

	res := p.rankAutoPool(autoPool, cs.LocalAddress)
	trace.AvgRTT = res.AvgRTT
	trace.CV = res.CV
	trace.Congested = res.Congested
	trace.NonLinear = res.NonLinear
	trace.M1, trace.M2 = res.M1, res.M2
	trace.PoolEligible = len(autoPool)
	trace.PoolFallback = len(res.Demoted)

	ingressIdx := mols.HashToGF64(cs.LocalAddress)
	demotedSet := make(map[string]bool, len(res.Demoted))
	for _, id := range res.Demoted {
		demotedSet[id] = true
	}

	for _, state := range autoPool {
		candidateIdx := mols.HashToGF64(state.Descriptor.APIHTTPSAddr)
		var score int
		if res.Congested {
			score = mols.CongestionScore(ingressIdx, candidateIdx, res.M1, res.M2, res.Order)
		} else {
			score = mols.Score(ingressIdx, candidateIdx, res.M1, res.M2, res.Order)
		}
		trace.Ranked = append(trace.Ranked, telemetry.TraceEntry{
			URL:       state.Descriptor.APIHTTPSAddr,
			Score:     score,
			Confirmed: state.Confirmed,
			RTT:       state.DiscoveryRTT,
			Demoted:   demotedSet[state.Descriptor.APIHTTPSAddr],
		})
	}

	autoURLs := make([]string, 0, len(res.Ordered))
	for _, c := range res.Ordered {
		autoURLs = append(autoURLs, c.ID)
	}
	if len(autoURLs) > cs.MultiHopDepth {
		autoURLs = autoURLs[:cs.MultiHopDepth]
	}
	trace.OutputURLs = autoURLs
	trace.SelectionTook = time.Since(start)
	return autoURLs, trace
}

// rankAutoPool maps RelayState candidates to the engine's flat Candidate type,
// evaluates saturation, and returns the ranked result.
func (p MOLSRelayPolicy) rankAutoPool(autoPool []discovery.RelayState, localAddress string) mols.RankResult {
	molsCandidates := make([]mols.Candidate, 0, len(autoPool))
	for _, state := range autoPool {
		state.EvaluateSaturation()
		molsCandidates = append(molsCandidates, p.toMOLSCandidate(state))
	}
	ingress := mols.Ingress{ID: localAddress, Index: mols.HashToGF64(localAddress)}
	return p.engine.Rank(ingress, molsCandidates)
}

func (p MOLSRelayPolicy) toMOLSCandidate(state discovery.RelayState) mols.Candidate {
	return mols.Candidate{
		ID:        state.Descriptor.APIHTTPSAddr,
		Index:     mols.HashToGF64(state.Descriptor.APIHTTPSAddr),
		RTT:       state.DiscoveryRTT,
		RTTAt:     state.DiscoveryRTTAt,
		Healthy:   !p.isRelayFallback(state),
		Saturated: state.IsSaturated,
		Confirmed: state.Confirmed,
	}
}

func (p MOLSRelayPolicy) isRelayFallback(state discovery.RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > p.engine.Config().FallbackRTTThreshold
}
