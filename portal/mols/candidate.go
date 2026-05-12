package mols

import "time"

// Candidate represents a single relay in the pool to be ranked.
// Callers map their domain-specific relay type to this flat struct.
type Candidate struct {
	ID        string        // opaque identifier, usually the relay URL
	Index     uint8         // pre-hashed column index (e.g. hashToGF64(ID))
	RTT       time.Duration // last measured round-trip time
	RTTAt     time.Time     // when RTT was measured; zero means missing
	Healthy   bool          // false → treated as fallback unless promoted
	Saturated bool          // saturated candidates are deprioritised within a tier
	Confirmed bool          // used as a tie-breaker during ranking
}

// Ingress identifies the client requesting the ranking.
type Ingress struct {
	ID    string // opaque ingress identity
	Index uint8  // pre-hashed row index (e.g. hashToGF64(ID))
}

// RankResult is the output of Engine.Rank.
type RankResult struct {
	Ordered   []Candidate
	Demoted   []string // candidates that stayed in the fallback tier after promotion
	Order     int      // grid order used for this ranking
	Congested bool
	NonLinear bool
	M1, M2    uint8
	AvgRTT    time.Duration
	CV        float64
}
