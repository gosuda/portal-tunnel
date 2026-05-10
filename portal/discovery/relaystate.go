package discovery

import (
	"sync/atomic"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/montanaflynn/stats"
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
	// stats.Percentile uses a highly optimized internal implementation
	val, err := stats.Percentile(pt.samples, p*100)
	if err != nil {
		return 0
	}
	return time.Duration(val)
}

type RelayState struct {
	Descriptor types.RelayDescriptor
	Bootstrap  bool
	Confirmed  bool
	Banned     bool
	LastSeenAt time.Time

	DiscoveryRTT   time.Duration
	DiscoveryRTTAt time.Time
	EWMARTT        time.Duration
	RTTTracker     PercentileTracker

	// SLIT LoadState
	LoadFactor  float64
	FailureRate float64
	IsSaturated bool
	loadFixed   uint32
	saturated   uint32

	discoveryFailures      int
	activeFailures         int
	nextDiscoveryRefreshAt time.Time
	suppressActiveUntil    time.Time
}

const (
	relayMetricScale         = 10000
	relaySaturationEnterLoad = 8000
	relaySaturationExitLoad  = 6000
)

func fixedLoad(load float64) uint32 {
	if load <= 0 {
		return 0
	}
	if load >= 1 {
		return relayMetricScale
	}
	return uint32(load*relayMetricScale + 0.5)
}

// StoreLoadFactor records load as fixed-point telemetry.
func (state *RelayState) StoreLoadFactor(loadFixed uint32) {
	if loadFixed > relayMetricScale {
		loadFixed = relayMetricScale
	}
	atomic.StoreUint32(&state.loadFixed, loadFixed)
	state.LoadFactor = float64(loadFixed) / relayMetricScale
}

func (state *RelayState) inheritAdaptiveTelemetry(existing RelayState) {
	load := atomic.LoadUint32(&existing.loadFixed)
	if load == 0 && existing.LoadFactor != 0 {
		load = fixedLoad(existing.LoadFactor)
	}
	state.StoreLoadFactor(load)
	state.IsSaturated = existing.IsSaturated || atomic.LoadUint32(&existing.saturated) == 1
	if state.IsSaturated {
		atomic.StoreUint32(&state.saturated, 1)
	}
}

// EvaluateSaturation applies load hysteresis:
// saturated above 0.8, active below 0.6, unchanged in the guard band.
func (state *RelayState) EvaluateSaturation() {
	load := atomic.LoadUint32(&state.loadFixed)
	if load == 0 && state.LoadFactor != 0 {
		load = fixedLoad(state.LoadFactor)
		atomic.StoreUint32(&state.loadFixed, load)
	}
	if state.IsSaturated {
		atomic.StoreUint32(&state.saturated, 1)
	}

	saturated := atomic.LoadUint32(&state.saturated)
	if load > relaySaturationEnterLoad {
		saturated = 1
	} else if load < relaySaturationExitLoad {
		saturated = 0
	}
	atomic.StoreUint32(&state.saturated, saturated)
	state.IsSaturated = saturated == 1
}

func (state *RelayState) UpdateEWMARTT(newRTT time.Duration) {
	const alpha = 0.3
	if state.EWMARTT == 0 {
		state.EWMARTT = newRTT
	} else {
		state.EWMARTT = time.Duration(float64(state.EWMARTT)*(1-alpha) + float64(newRTT)*alpha)
	}
	state.RTTTracker.Add(newRTT)
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
