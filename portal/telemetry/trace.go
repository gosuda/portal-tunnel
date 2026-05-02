package telemetry

import "time"

// SelectionTrace records observability data for a single relay-selection
// invocation.
type SelectionTrace struct {
	Timestamp time.Time

	// ClientHash is hashToGF64(LocalAddress) — a single byte derived from the
	// client identity. Used only for sampled debug-log correlation. Not a
	// Prometheus label (would unbounded cardinality) and not a public field on
	// any external API.
	ClientHash uint8

	// Mode is "priority" or "multihop", matching the calling method.
	Mode string

	// Pool snapshot at selection time.
	PoolTotal    int
	PoolEligible int
	PoolFallback int

	// Suppressed lists URLs excluded from selection along with the reason map.
	Suppressed []string
	Reasons    map[string]string

	// Congested is true when the existing congestion-grid switch is active
	// (RTT mean > molsCongestionRTTThreshold).
	Congested bool

	// NonLinear is true when the variant-grid multiplier flip is active
	// (CV > molsCVThreshold).
	NonLinear bool

	// M1, M2 are the MOLS multipliers used for this selection.
	M1, M2 uint8

	// AvgRTT is the mean discovery RTT across the auto pool sample.
	AvgRTT time.Duration

	// CV is the coefficient of variation of per-relay discovery RTTs.
	CV float64

	// Ranked carries per-relay scoring detail for every candidate considered
	// (excluded URLs appear in Suppressed/Reasons instead).
	Ranked []TraceEntry

	// OutputURLs is the final ordered list returned by the selection method.
	OutputURLs []string

	// SelectionTook is wall time spent in the selection method.
	SelectionTook time.Duration
}

// TraceEntry captures per-relay scoring detail within a SelectionTrace.
type TraceEntry struct {
	URL       string
	Score     int
	Confirmed bool
	RTT       time.Duration
	Demoted   bool
}
