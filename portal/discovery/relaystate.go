package discovery

import (
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	DiscoveryDescriptorTTL       = 5 * time.Minute
	defaultDirectRecoveryBackoff = 1 * time.Minute
	maxDirectRecoveryBackoff     = 5 * time.Minute
	relayPoolBanTTL              = 72 * time.Hour

	// MaxAnnouncedRelays is the hard ceiling on the number of relay entries
	// the local set will retain. When exceeded, eviction prefers the oldest
	// unverified entries by LastSeenAt, then verified entries. Bootstrap and
	// banned entries are pinned.
	MaxAnnouncedRelays = 1024

	// MaxAnnouncedRelaysPerIdentity bounds how many unverified announced
	// entries one signing identity may hold. Overflow recycles that
	// identity's own oldest entries, so an unauthenticated announce or
	// hop-route flood cannot use the identity's slots to push other relays
	// toward the global-cap eviction.
	MaxAnnouncedRelaysPerIdentity = 4

	// AnnounceClockSkewTolerance bounds how far in the future a descriptor's
	// IssuedAt may sit relative to local time. Anything beyond this is
	// rejected as clock-skewed or maliciously post-dated.
	AnnounceClockSkewTolerance = 5 * time.Minute

	// AnnounceMaxValidity bounds the maximum (ExpiresAt - IssuedAt) window
	// for an accepted announce. Honest relays sign with the discovery TTL,
	// so a 24h cap leaves ample headroom while preventing attackers from
	// minting year-long descriptors.
	AnnounceMaxValidity = 24 * time.Hour
)

// RelayTrust classifies whether this relay has directly verified a pool
// entry or only received its descriptor from untrusted input. Verifying a
// relay never verifies the other relays its discovery response mentions;
// those are admitted as candidates like any other untrusted descriptor.
type RelayTrust uint8

const (
	// RelayCandidate marks a descriptor admitted from untrusted input.
	// Candidates remain refresh-poll targets, but they are excluded from
	// Descriptors(), automatic route selection, and this relay's own gossip
	// output until promoted.
	RelayCandidate RelayTrust = iota

	// RelayVerified marks a relay whose own URL this relay polled directly
	// and which served a validly signed self-descriptor. Verified entries
	// are globally discoverable and automatically selectable.
	RelayVerified
)

type PercentileTracker struct {
	samples []float64
}

func (pt *PercentileTracker) Add(rtt time.Duration) {
	pt.samples = append(pt.samples, float64(rtt))
	if len(pt.samples) > 100 { // Keep last 100 samples
		pt.samples = pt.samples[1:]
	}
}

func (pt *PercentileTracker) Get(p float64) time.Duration {
	if len(pt.samples) == 0 {
		return 0
	}
	if len(pt.samples) == 1 {
		return time.Duration(pt.samples[0])
	}
	percent := p * 100
	if !(percent > 0 && percent <= 100) {
		return 0
	}

	// Sort a bounded scratch copy so querying a percentile preserves the
	// arrival order used to evict samples. Interpolate between closest ranks.
	var scratch [100]float64
	samples := scratch[:len(pt.samples)]
	copy(samples, pt.samples)
	slices.Sort(samples)
	rank := (percent / 100) * float64(len(samples)-1)
	k := int(rank)
	value := samples[k]
	if k+1 < len(samples) {
		value += (rank - float64(k)) * (samples[k+1] - samples[k])
	}
	return time.Duration(value)
}

type RelayState struct {
	Descriptor types.RelayDescriptor
	Bootstrap  bool
	// Trust classifies how the entry entered the set. Descriptors from
	// untrusted input (/discovery/announce or gossiped discovery
	// content) are admitted as RelayCandidate and stay out of Descriptors()
	// and automatic route selection until a direct authoritative probe of
	// that exact relay promotes them to RelayVerified.
	Trust  RelayTrust
	Banned bool
	// recovery budget. Dead relays are excluded from route planning and relay
	// listings but stay in the set: the refresher keeps probing them and a
	// successful discovery response clears the mark.
	Dead       bool
	LastSeenAt time.Time

	DiscoveryRTT   time.Duration
	DiscoveryRTTAt time.Time
	RTTTracker     PercentileTracker

	discoveryFailures      int
	activeFailures         int
	unhealthySince         time.Time
	nextDiscoveryRefreshAt time.Time
	suppressActiveUntil    time.Time
}

const (
	failurePenaltyRTT = 300 * time.Millisecond
	maxFailurePenalty = 3 * time.Second
)

// effectiveRTT computes the relay's RTT with a virtual latency penalty applied for active and discovery failures.
func (state RelayState) effectiveRTT() time.Duration {
	rtt := state.DiscoveryRTT
	failures := state.activeFailures + state.discoveryFailures
	if failures > 0 {
		penalty := time.Duration(failures) * failurePenaltyRTT
		if penalty > maxFailurePenalty {
			penalty = maxFailurePenalty
		}
		rtt += penalty
	}
	return rtt
}

// Pressure measures observed tail latency inflation relative to the median.
func (state RelayState) Pressure() float64 {
	p50 := float64(state.RTTTracker.Get(0.50))
	p90 := float64(state.RTTTracker.Get(0.90))

	if p50 > 0 && p90 > p50 {
		return (p90 - p50) / p50
	}
	return 0
}

func newRelayState(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
	}
}

func (state RelayState) hasObservedDescriptor() bool {
	return !state.LastSeenAt.IsZero()
}

type routeState struct {
	ExplicitRelayURLs []string
	// ActiveRelayURLs holds currently active connected relay URLs to enable
	// connection-level stickiness and prevent listener churn during ranking updates.
	ActiveRelayURLs []string
	// MaxActiveRelays caps auto-selected listener entries. Zero or negative
	// values use the selection default of 3.
	MaxActiveRelays int
	RequireUDP      bool
	RequireTCP      bool
	// LocalAddress is the ingress identity address used by MOLS route selection to
	// derive a deterministic row index into the MOLS grid.
	LocalAddress string
	// SelectionSalt is the per-client secret mixed into all MOLS hashes. It
	// makes rankings unpredictable to outside observers and immune to relay
	// URL grinding; the sdk derives a stable value from the identity private key.
	SelectionSalt uint64
}

func (state RelayState) supportsRequiredTransports(routeState routeState, now time.Time) bool {
	if !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) {
		return true
	}
	return (!routeState.RequireUDP || state.Descriptor.SupportsUDP) &&
		(!routeState.RequireTCP || state.Descriptor.SupportsTCP)
}
