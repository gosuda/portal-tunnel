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

func (state RelayState) hasObservedDescriptor() bool {
	return !state.LastSeenAt.IsZero()
}

type ClientState struct {
	ExplicitRelayURLs []string
	// SuppressedRelayURLs are discovery seeds that must not be auto-selected
	// as active relays unless they are also explicit.
	SuppressedRelayURLs []string
	// MaxActiveRelays caps auto-selected relays. Zero or negative values use
	// the policy default of 3.
	MaxActiveRelays int
	MultiHopDepth   int
	RequireUDP      bool
	RequireTCP      bool
	// LocalAddress is the ingress identity address used by MOLSRelayPolicy to
	// derive a deterministic row index into the GF(64) MOLS grid.
	LocalAddress string
}
