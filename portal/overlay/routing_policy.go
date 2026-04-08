package overlay

import (
	"errors"
	"math"
	"sort"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
)

const (
	molsFieldDegree   = 6
	molsSize          = 1 << molsFieldDegree // order-64 MOLS grid
	molsMask          = molsSize - 1
	molsPrimitivePoly = 0b1000011 // x^6 + x + 1

	// minTopologyNodes is the minimum number of non-fallback nodes that must
	// remain active in the MOLS topology at all times.
	minTopologyNodes = 2

	// variantMultiplierA/B are alternative GF(64) multipliers used to build
	// the non-linear load MOLS variant grid (different Latin pair than 3,5).
	variantMultiplierA uint8 = 7
	variantMultiplierB uint8 = 11

	// nonLinearCVThreshold is the coefficient-of-variation threshold above
	// which per-node latency distribution is treated as non-linear/bursty.
	nonLinearCVThreshold = 0.5
)

// RoutePolicy selects overlay relay hops using an order-64 MOLS-derived magic
// square. During congestion it switches to the reverse-Siamese complement grid
// (B(i,j)=c-A(i,n+1-j)). When per-node latency distribution is non-linear
// (high coefficient of variation), it uses a variant MOLS built with a
// different GF(64) multiplier pair.
type RoutePolicy struct {
	magic   []uint16
	reverse []uint16
	variant []uint16 // non-linear load variant (multipliers 7, 11)

	mu    sync.RWMutex
	nodes map[uint32]policy.RelayHealth
}

func NewRoutePolicy() *RoutePolicy {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	ensureMagicSquare(magic)
	reverse := deriveReverseSiameseGrid(magic)
	variant := buildMagicOrthogonalLatinGrid(variantMultiplierA, variantMultiplierB)
	ensureMagicSquare(variant)
	return &RoutePolicy{
		magic:   magic,
		reverse: reverse,
		variant: variant,
		nodes:   make(map[uint32]policy.RelayHealth),
	}
}

// UpdateNodeHealth registers or updates the health metrics for a relay node.
func (p *RoutePolicy) UpdateNodeHealth(nodeID uint32, h policy.RelayHealth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes[nodeID] = h
}

// ActiveNodeCount returns the number of nodes currently not marked as fallback.
func (p *RoutePolicy) ActiveNodeCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, h := range p.nodes {
		if !h.Fallback {
			count++
		}
	}
	return count
}

// MarkSlowFallback demotes nodeID to last-resort status so that BuildRoute
// prefers other nodes. The demotion is refused if it would reduce the active
// (non-fallback) node count below minTopologyNodes; in that case the method
// returns false.
func (p *RoutePolicy) MarkSlowFallback(nodeID uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, known := p.nodes[nodeID]
	if !known || h.Fallback {
		return false
	}
	// Count active nodes excluding nodeID.
	active := 0
	for id, nh := range p.nodes {
		if id != nodeID && !nh.Fallback {
			active++
		}
	}
	if active < minTopologyNodes {
		return false
	}
	h.Fallback = true
	p.nodes[nodeID] = h
	return true
}

// isNonLinearLoad returns true when the per-node ping-latency distribution
// has a coefficient of variation above nonLinearCVThreshold, indicating
// that load is uneven or bursty rather than uniformly distributed.
func (p *RoutePolicy) isNonLinearLoad() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var sum float64
	var count int
	for _, h := range p.nodes {
		if h.PingLatencyMs > 0 {
			sum += h.PingLatencyMs
			count++
		}
	}
	if count < 2 {
		return false
	}
	mean := sum / float64(count)
	if mean == 0 {
		return false
	}
	var variance float64
	for _, h := range p.nodes {
		if h.PingLatencyMs > 0 {
			d := h.PingLatencyMs - mean
			variance += d * d
		}
	}
	variance /= float64(count)
	cv := math.Sqrt(variance) / mean
	return cv > nonLinearCVThreshold
}

// selectGrid picks the appropriate MOLS grid based on load mode.
// Non-linear load takes precedence over congestion so that bursty traffic
// uses the variant Siamese arrangement.
func (p *RoutePolicy) selectGrid(congested, nonLinear bool) []uint16 {
	switch {
	case nonLinear:
		return p.variant
	case congested:
		return p.reverse
	default:
		return p.magic
	}
}

// BuildRoute returns [ingress, hop1, hop2, ...]. maxHops is the number of
// relays after ingress and is clamped to [1, len(candidates)].
//
// Candidates are split into active (non-fallback, healthy) and fallback
// pools. Active nodes are scored first using the selected MOLS grid; fallback
// nodes are appended after so they are chosen only when no active node fits.
// At least one hop is always returned as long as candidates is non-empty.
func (p *RoutePolicy) BuildRoute(ingress uint32, candidates []uint32, maxHops int, congested bool) ([]uint32, error) {
	if len(candidates) == 0 {
		return nil, errors.New("candidates empty")
	}
	if maxHops <= 0 {
		maxHops = 1
	}
	if maxHops > len(candidates) {
		maxHops = len(candidates)
	}

	nonLinear := p.isNonLinearLoad()
	grid := p.selectGrid(congested, nonLinear)

	p.mu.RLock()
	row := int(ingress & molsMask)
	activeScores := make([]scoredNode, 0, len(candidates))
	fallbackScores := make([]scoredNode, 0)
	for _, nodeID := range candidates {
		col := int(nodeID & molsMask)
		score := grid[row*molsSize+col]
		h, known := p.nodes[nodeID]
		// Fallback and unhealthy nodes are placed in the fallback pool so they
		// are used as last-resort rather than excluded entirely. This ensures
		// routing never stalls even when all known nodes are degraded; it also
		// satisfies the minimum-2-nodes topology requirement.
		if known && (h.Fallback || !h.Healthy) {
			fallbackScores = append(fallbackScores, scoredNode{nodeID: nodeID, score: score})
		} else {
			activeScores = append(activeScores, scoredNode{nodeID: nodeID, score: score})
		}
	}
	p.mu.RUnlock()

	sortScored(activeScores)
	sortScored(fallbackScores)

	// Merge: active first, then fallback. If there are no active nodes at all,
	// fall through to fallback so routing never stalls.
	merged := append(activeScores, fallbackScores...)

	route := make([]uint32, 0, maxHops+1)
	route = append(route, ingress)
	for i := 0; i < maxHops; i++ {
		route = append(route, merged[i].nodeID)
	}
	return route, nil
}

// BuildRouteWithLoad applies the reverse-Siamese congestion trigger:
// switch to the reverse grid when average latency exceeds threshold.
// Non-linear load is detected automatically from per-node health data inside
// BuildRoute; no additional caller action is required.
func (p *RoutePolicy) BuildRouteWithLoad(ingress uint32, candidates []uint32, maxHops int, load policy.NodeLoad, congestionLatencyMs float64) ([]uint32, error) {
	congested := load.AvgLatencyMs >= congestionLatencyMs
	return p.BuildRoute(ingress, candidates, maxHops, congested)
}

type scoredNode struct {
	nodeID uint32
	score  uint16
}

func sortScored(s []scoredNode) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].score == s[j].score {
			return s[i].nodeID < s[j].nodeID
		}
		return s[i].score < s[j].score
	})
}

func gfMul(a, b uint8) uint8 {
	res := uint8(0)
	for b != 0 {
		if b&1 == 1 {
			res ^= a
		}
		b >>= 1
		a <<= 1
		if a&uint8(molsSize) != 0 {
			a ^= molsPrimitivePoly
		}
		a &= uint8(molsMask)
	}
	return res & uint8(molsMask)
}

func buildGFLatin(multiplier uint8) []uint8 {
	square := make([]uint8, molsSize*molsSize)
	for i := 0; i < molsSize; i++ {
		for j := 0; j < molsSize; j++ {
			square[i*molsSize+j] = uint8(i) ^ gfMul(multiplier, uint8(j))
		}
	}
	return square
}

func buildMagicOrthogonalLatinGrid(multiplierA, multiplierB uint8) []uint16 {
	latinA := buildGFLatin(multiplierA)
	latinB := buildGFLatin(multiplierB)
	grid := make([]uint16, molsSize*molsSize)
	for i := range grid {
		grid[i] = uint16(latinA[i])*molsSize + uint16(latinB[i]) + 1
	}
	return grid
}

func ensureMagicSquare(grid []uint16) {
	if !isMagicSquare(grid) {
		panic("overlay: orthogonal latin grid must remain a magic square")
	}
}

func isMagicSquare(grid []uint16) bool {
	if len(grid) != molsSize*molsSize {
		return false
	}
	target := molsSize * (molsSize*molsSize + 1) / 2
	seen := make([]bool, len(grid))
	mainDiag := 0
	antiDiag := 0

	for row := 0; row < molsSize; row++ {
		rowSum := 0
		for col := 0; col < molsSize; col++ {
			idx := row*molsSize + col
			val := int(grid[idx])
			if val <= 0 || val > len(grid) {
				return false
			}
			if seen[val-1] {
				return false
			}
			seen[val-1] = true
			rowSum += val
			if row == col {
				mainDiag += val
			}
			if row+col == molsSize-1 {
				antiDiag += val
			}
		}
		if rowSum != target {
			return false
		}
	}
	for col := 0; col < molsSize; col++ {
		colSum := 0
		for row := 0; row < molsSize; row++ {
			colSum += int(grid[row*molsSize+col])
		}
		if colSum != target {
			return false
		}
	}
	if mainDiag != target || antiDiag != target {
		return false
	}
	for _, seenVal := range seen {
		if !seenVal {
			return false
		}
	}
	return true
}

func deriveReverseSiameseGrid(square []uint16) []uint16 {
	out := make([]uint16, len(square))
	complementConst := uint16(len(square) + 1)
	for row := 0; row < molsSize; row++ {
		for col := 0; col < molsSize; col++ {
			src := row*molsSize + (molsSize - 1 - col)
			out[row*molsSize+col] = complementConst - square[src]
		}
	}
	return out
}
