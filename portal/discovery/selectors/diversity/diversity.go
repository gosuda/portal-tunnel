// Package diversity provides a discovery.Selector wrapper that enforces
// multi-hop path diversity on top of any inner selector. It does NOT modify
// SelectPriority — single-hop priority selection is passed through unchanged.
//
// # Role Separation (default-on)
//
// When client.DisableDiversityRoles is false (the default), SelectMultiHop
// enforces URL-uniqueness across hops: entry, transit, and exit relays must
// all have distinct URLs. This surfaces the user-reported symptom that
// unguarded multi-hop selection has "no control basis".
//
// # Anonymity Grade (opt-in)
//
// When client.AnonymityGrade is true, the selector additionally enforces that
// no two selected relays share the same Subnet16 or Family value. Empty
// Subnet16 / Family values contribute no constraint (relax-by-omission: a
// relay without metadata doesn't block others, it simply doesn't consume a
// diversity slot).
//
// # Candidate Pool
//
// The walk function first consumes innerURLs (the inner selector's preference
// ordering) and then falls through to remaining pool entries (sorted by URL
// for determinism) if innerURLs is exhausted before MultiHopDepth is reached.
// This ensures that valid diverse relays available in the pool are not ignored
// just because the inner selector returned a trimmed top-N list.
//
// # Relaxation
//
// When the combined candidate set (innerURLs + remaining pool) is still too
// small to satisfy a constraint, the selector relaxes gracefully:
//
//  1. AnonymityGrade shortfall: retry the walk without AnonymityGrade.
//     Increments portal_discovery_diversity_relaxed_total{reason="anonymity_grade"}.
//
//  2. Role-separation shortfall: the pool has fewer distinct URLs than
//     MultiHopDepth. Fall back to the inner result directly (which may contain
//     duplicates). Increments portal_discovery_diversity_relaxed_total{reason="role_separation"}.
//
// The relaxation order is (AnonymityGrade, then role-separation) so the
// strongest constraint is dropped first.
package diversity

import (
	"context"
	"sort"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
)

// Diversity wraps an inner Selector and adds hop-path diversity enforcement
// for multi-hop selections.
type Diversity struct {
	inner discovery.Selector
}

// Option is a functional option for Diversity (reserved for future extension).
type Option func(*Diversity)

// New returns a new Diversity selector wrapping inner. Any Options are applied
// in order after the Diversity is initialised.
func New(inner discovery.Selector, opts ...Option) *Diversity {
	d := &Diversity{inner: inner}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Compile-time assertion: *Diversity must satisfy discovery.Selector.
var _ discovery.Selector = (*Diversity)(nil)

// Name returns the inner selector's name with "+diversity" appended.
func (d *Diversity) Name() string { return d.inner.Name() + "+diversity" }

// SelectPriority passes through to the inner selector unchanged. Single-hop
// priority selection does not benefit from diversity wrapping.
func (d *Diversity) SelectPriority(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	return d.inner.SelectPriority(ctx, pool, client)
}

// SelectMultiHop delegates to the inner selector and then applies diversity
// filtering according to client.DisableDiversityRoles and client.AnonymityGrade.
//
// The candidate set passed to the walk is: innerURLs first (respecting the
// inner selector's preference ordering), then any pool entries not already
// in innerURLs (sorted by URL for determinism). This ensures pool-wide diverse
// candidates are not missed when the inner returns only a trimmed top-N list.
//
// The returned trace is the inner trace with OutputURLs updated to the
// post-diversity result, plus any relaxation notes appended to Reasons.
func (d *Diversity) SelectMultiHop(ctx context.Context, pool []discovery.RelayState, client discovery.ClientState) ([]string, discovery.SelectionTrace) {
	innerURLs, trace := d.inner.SelectMultiHop(ctx, pool, client)

	// Early exit: no depth, no inner result.
	if client.MultiHopDepth < 2 || len(innerURLs) == 0 {
		return innerURLs, trace
	}

	// Build a URL → RelayState lookup for O(1) access.
	stateByURL := make(map[string]discovery.RelayState, len(pool))
	for _, rs := range pool {
		stateByURL[rs.Descriptor.APIHTTPSAddr] = rs
	}

	// Build the full candidate ordering:
	// 1. innerURLs in the order the inner selector returned them.
	// 2. Remaining pool entries (sorted by URL for determinism) not in innerURLs.
	candidates := buildCandidates(innerURLs, pool)

	// Attempt 1: full constraints (role-separation + AnonymityGrade if set).
	out, ok := walk(candidates, stateByURL, client)
	if ok {
		trace.OutputURLs = out
		return out, trace
	}

	// Relaxation step (a): if AnonymityGrade was on, retry without it.
	if client.AnonymityGrade {
		discovery.DiversityRelaxedTotal.WithLabelValues("anonymity_grade").Inc()
		relaxedClient := client
		relaxedClient.AnonymityGrade = false
		out, ok = walk(candidates, stateByURL, relaxedClient)
		if ok {
			if trace.Reasons == nil {
				trace.Reasons = make(map[string]string)
			}
			trace.Reasons["diversity_relaxed"] = "anonymity_grade"
			trace.OutputURLs = out
			return out, trace
		}
	}

	// Relaxation step (b): role-separation shortfall — fall back to inner result.
	if !client.DisableDiversityRoles {
		discovery.DiversityRelaxedTotal.WithLabelValues("role_separation").Inc()
		if trace.Reasons == nil {
			trace.Reasons = make(map[string]string)
		}
		trace.Reasons["diversity_relaxed"] = "role_separation"
	}
	trace.OutputURLs = innerURLs
	return innerURLs, trace
}

// buildCandidates returns an ordered candidate slice: innerURLs first, then
// any pool entries not in innerURLs sorted by URL for determinism.
func buildCandidates(innerURLs []string, pool []discovery.RelayState) []string {
	inInner := make(map[string]struct{}, len(innerURLs))
	for _, u := range innerURLs {
		inInner[u] = struct{}{}
	}

	// Collect extras in sorted order for determinism.
	extras := make([]string, 0, len(pool))
	for _, rs := range pool {
		u := rs.Descriptor.APIHTTPSAddr
		if _, seen := inInner[u]; !seen {
			extras = append(extras, u)
		}
	}
	sort.Strings(extras)

	result := make([]string, 0, len(innerURLs)+len(extras))
	result = append(result, innerURLs...)
	result = append(result, extras...)
	return result
}

// walk applies diversity filtering to candidates and returns the first
// client.MultiHopDepth entries that satisfy role-separation and (if enabled)
// AnonymityGrade constraints. Returns (out, true) when len(out)==depth, or
// (partial, false) on shortfall.
func walk(
	candidates []string,
	stateByURL map[string]discovery.RelayState,
	client discovery.ClientState,
) ([]string, bool) {
	depth := client.MultiHopDepth
	roleCheck := !client.DisableDiversityRoles
	anonCheck := client.AnonymityGrade

	out := make([]string, 0, depth)
	usedURLs := make(map[string]struct{}, depth)
	usedSubnets := make(map[string]struct{}, depth)
	usedFamilies := make(map[string]struct{}, depth)

	for _, url := range candidates {
		if len(out) >= depth {
			break
		}

		// Role-separation: reject duplicate URLs.
		if roleCheck {
			if _, dup := usedURLs[url]; dup {
				continue
			}
		}

		// AnonymityGrade: reject if Subnet16 or Family already used.
		if anonCheck {
			if rs, ok := stateByURL[url]; ok {
				if s := rs.Descriptor.Subnet16; s != "" {
					if _, seen := usedSubnets[s]; seen {
						continue
					}
				}
				if f := rs.Descriptor.Family; f != "" {
					if _, seen := usedFamilies[f]; seen {
						continue
					}
				}
			}
		}

		// Accept this relay.
		out = append(out, url)
		usedURLs[url] = struct{}{}
		if anonCheck {
			if rs, ok := stateByURL[url]; ok {
				if s := rs.Descriptor.Subnet16; s != "" {
					usedSubnets[s] = struct{}{}
				}
				if f := rs.Descriptor.Family; f != "" {
					usedFamilies[f] = struct{}{}
				}
			}
		}
	}

	return out, len(out) >= depth
}
