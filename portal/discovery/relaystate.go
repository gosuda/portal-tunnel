package discovery

import (
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	DiscoveryDescriptorTTL       = 5 * time.Minute
	defaultDirectRecoveryBackoff = 1 * time.Minute
	maxDirectRecoveryBackoff     = 5 * time.Minute

	// MaxAnnouncedRelays is the hard ceiling on the number of relay entries
	// the local set will retain. When exceeded, eviction prefers the oldest
	// non-bootstrap, non-confirmed entries by LastSeenAt. Bootstrap and
	// listener-confirmed entries are pinned and never evicted by capacity.
	MaxAnnouncedRelays = 1024

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

type RelayState struct {
	Descriptor types.RelayDescriptor
	Bootstrap  bool
	Confirmed  bool
	Banned     bool
	LastSeenAt time.Time

	DiscoveryRTT   time.Duration
	DiscoveryRTTAt time.Time

	// EWMA load surface (Phase 2). Owned by Lifecycle; selectors read but
	// never mutate. Protection comes from RelaySet.mu via the Lifecycle
	// concurrency contract documented at portal/discovery/lifecycle.go.
	LoadFactor  float64   // EWMA of (active_tunnels / pool_avg) + (failure_rate * beta)
	FailureRate float64   // EWMA of failure events per discovery + active path
	LastUpdated time.Time // wall clock for tau-based decay

	discoveryFailures      int
	activeFailures         int
	nextDiscoveryRefreshAt time.Time
	suppressActiveUntil    time.Time
}

func newRelayState(relayURL string) RelayState {
	return RelayState{
		Descriptor: types.RelayDescriptor{
			APIHTTPSAddr: relayURL,
		},
	}
}

// HasObservedDescriptor reports whether the relay has ever been directly
// observed (i.e. LastSeenAt is non-zero).
func (state RelayState) HasObservedDescriptor() bool {
	return !state.LastSeenAt.IsZero()
}

// IsSuppressedActive reports whether the relay is currently in active
// suppression (back-off) at the given time.
func (state RelayState) IsSuppressedActive(now time.Time) bool {
	return !state.suppressActiveUntil.IsZero() && state.suppressActiveUntil.After(now)
}

type ClientState struct {
	ExplicitRelayURLs []string
	// MaxActiveRelays caps auto-selected relays. Zero or negative values use
	// the policy default of 3.
	MaxActiveRelays int
	MultiHopDepth   int
	RequireUDP      bool
	RequireTCP      bool
	// LocalAddress is the ingress identity address used by the relay selector to
	// derive a deterministic row index into the GF(64) MOLS grid.
	LocalAddress string

	// DisableDiversityRoles opts out of role separation in multi-hop paths.
	// Default false (i.e. role separation is ENABLED by default). When false,
	// the diversity selector enforces URL-uniqueness across hops so that entry,
	// transit, and exit relays are always distinct. Set to true only when you
	// explicitly want to allow duplicate relays in a path (e.g. load tests that
	// intentionally exhaust the relay pool below MultiHopDepth). This inverted
	// field name is used to make the zero value of ClientState the safe default
	// (role separation on).
	DisableDiversityRoles bool

	// AnonymityGrade opts in to /16-prefix + operator-family diversity on
	// multi-hop paths. Default false (disabled). When true, the diversity
	// selector additionally enforces that no two selected relays share the same
	// Subnet16 or Family value (ignoring empty values, which contribute no
	// constraint). A shortfall caused by this constraint triggers relaxation
	// and increments portal_discovery_diversity_relaxed_total{reason="anonymity_grade"}.
	AnonymityGrade bool
}
