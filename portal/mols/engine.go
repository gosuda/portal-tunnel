package mols

// Engine is the pure MOLS ranking engine.  It owns no relay-domain state; it
// receives a flat candidate slice, scores it deterministically, and returns an
// ordered result.
//
// The ranking pipeline is hierarchically isolated:
//  1. Classify  (adaptive strategy)
//  2. Partition (active vs fallback tiers)
//  3. Score     (MOLS grid)
//  4. Rank      (per-tier ordering with saturation deprioritisation)
type Engine struct {
	cfg      Config
	strategy AdaptiveStrategy
}

// maxStackDepth is the largest depth for which rankTier uses a stack-allocated
// array instead of a heap slice.  Tuned for the default CandidateDepth (8) and
// typical production depths (≤16) to stay off the GOGC heap in the hot path.
const maxStackDepth = 16

// NewEngine creates an Engine.  If strategy is nil, DefaultAdaptiveStrategy is used.
func NewEngine(cfg Config, strategy AdaptiveStrategy) *Engine {
	if strategy == nil {
		strategy = DefaultAdaptiveStrategy{}
	}
	return &Engine{cfg: cfg, strategy: strategy}
}

// Config returns a copy of the engine's current configuration.
func (e *Engine) Config() Config {
	return e.cfg
}

// Rank runs the full MOLS pipeline for the given ingress and candidate pool.
// The returned slice contains candidates ordered from most to least preferred.
func (e *Engine) Rank(ingress Ingress, candidates []Candidate) RankResult {
	if len(candidates) == 0 {
		return RankResult{}
	}

	congested, nonLinear, avgRTT, cv := e.strategy.Classify(candidates, e.cfg)
	m1, m2 := e.strategy.SelectMultipliers(nonLinear, e.cfg)

	active, fallback := e.strategy.Partition(candidates, e.cfg)

	order := gridOrderForSize(len(candidates))
	scoreFor := func(c Candidate) int {
		if congested {
			return molsCongestionScore(int(ingress.Index)%order, int(c.Index)%order, int(m1), int(m2), order)
		}
		return molsScore(int(ingress.Index)%order, int(c.Index)%order, int(m1), int(m2), order)
	}

	activeRanked := rankTier(active, scoreFor, e.cfg.CandidateDepth)
	fallbackRanked := rankTier(fallback, scoreFor, e.cfg.CandidateDepth)

	demoted := make([]string, 0, len(fallbackRanked))
	for _, c := range fallbackRanked {
		demoted = append(demoted, c.ID)
	}

	ordered := make([]Candidate, 0, len(activeRanked)+len(fallbackRanked))
	ordered = append(ordered, activeRanked...)
	ordered = append(ordered, fallbackRanked...)

	return RankResult{
		Ordered:   ordered,
		Demoted:   demoted,
		Order:     order,
		Congested: congested,
		NonLinear: nonLinear,
		M1:        m1,
		M2:        m2,
		AvgRTT:    avgRTT,
		CV:        cv,
	}
}

// rankTier orders a single tier using fixed-depth insertion sort.  Saturated
// candidates are pushed behind non-saturated ones while the intra-tier MOLS
// order is otherwise preserved.
func rankTier(candidates []Candidate, scoreFor func(Candidate) int, depth int) []Candidate {
	if len(candidates) == 0 {
		return nil
	}

	type slot struct {
		c     Candidate
		score int
		seq   int
	}

	better := func(a, b slot) bool {
		if a.score != b.score {
			return a.score > b.score
		}
		if a.c.Confirmed != b.c.Confirmed {
			return a.c.Confirmed
		}
		if a.c.ID != b.c.ID {
			return a.c.ID < b.c.ID
		}
		return a.seq < b.seq
	}

	// Use a stack-allocated array for the common case to reduce GOGC pressure.
	var stackBuf [maxStackDepth]slot
	var buf []slot
	if depth <= maxStackDepth {
		buf = stackBuf[:0]
	} else {
		buf = make([]slot, 0, depth)
	}

	for i, c := range candidates {
		s := slot{c: c, score: scoreFor(c), seq: i}
		insertAt := len(buf)
		for insertAt > 0 && better(s, buf[insertAt-1]) {
			insertAt--
		}
		if insertAt >= depth {
			continue
		}
		if len(buf) < depth {
			buf = append(buf, slot{})
		}
		copy(buf[insertAt+1:], buf[insertAt:len(buf)-1])
		buf[insertAt] = s
	}

	out := make([]Candidate, 0, len(buf))
	for _, s := range buf {
		if !s.c.Saturated {
			out = append(out, s.c)
		}
	}
	for _, s := range buf {
		if s.c.Saturated {
			out = append(out, s.c)
		}
	}
	return out
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
