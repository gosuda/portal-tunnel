package policy

// NodeLoad aggregates instantaneous and derived load metrics for a relay.
// It is shared between LoadManager (network counters) and WeightManager
// (latency/error composition) so callers can merge their views before
// making balancing decisions.
type NodeLoad struct {
	ActiveConns  int64
	BytesIn      int64
	BytesOut     int64
	ConnRate     float64
	AvgLatencyMs float64
	// JitterMs is the mean delay variance across all registered contributors.
	// A high JitterMs relative to AvgLatencyMs indicates non-linear bursty load.
	JitterMs float64
}
