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
}
