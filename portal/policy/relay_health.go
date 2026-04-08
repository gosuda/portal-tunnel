package policy

// RelayHealth captures per-relay health metrics used by the MOLS-based
// routing policy to score and demote individual relay nodes.
type RelayHealth struct {
	// RTTMs is the measured round-trip time for data traversal in milliseconds.
	RTTMs float64
	// PingLatencyMs is the one-way ping latency observed for this relay in
	// milliseconds. 0 means no measurement is available.
	PingLatencyMs float64
	// Healthy reports whether the relay is currently reachable and responding
	// to keepalives.
	Healthy bool
	// ErrorPct is the fraction of packets received from this relay that
	// carried an error indicator (0 = no errors, 1 = all packets errored).
	ErrorPct float64
	// Fallback marks this node as last-resort: it is only included in a route
	// when no other nodes are available. The topology always maintains at least
	// two non-fallback nodes; MarkSlowFallback refuses to demote below that
	// minimum.
	Fallback bool
}
