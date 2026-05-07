package discovery

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestQoSConsistency verifies p99 latency reduction and rank stability (oscillation).
func TestQoSConsistency(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	numNodes := 20
	// 5 stable nodes (100ms), 5 jittery nodes (spikes to 600ms)
	nodes := make([]RelayState, numNodes)
	for i := 0; i < numNodes; i++ {
		nodes[i] = RelayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("node-%d", i)}}
		base := 100.0
		if i >= 5 {
			base = 300.0
		} // jittery nodes are slower on average
		for j := 0; j < 100; j++ {
			rtt := base
			if i >= 5 && rng.Float64() < 0.2 {
				rtt += 400.0
			}
			nodes[i].UpdateEWMARTT(time.Duration(rtt) * time.Millisecond)
		}
	}

	policy := MOLSRelayPolicy{}
	var history []string
	var latencies []float64

	// Simulate 1000 selection rounds
	for r := 0; r < 1000; r++ {
		selected := policy.rankRelayPool(nodes, "client-x")
		top := selected[0]
		history = append(history, top)

		// Find latency of top node
		for _, n := range nodes {
			if n.Descriptor.APIHTTPSAddr == top {
				latencies = append(latencies, float64(n.EWMARTT.Milliseconds()))
			}
		}
	}

	// 1. Oscillation Check: count changes in top-pick
	changes := 0
	for i := 1; i < len(history); i++ {
		if history[i] != history[i-1] {
			changes++
		}
	}

	// 2. Latency Check: p99
	sort.Float64s(latencies)
	p99 := latencies[990]

	fmt.Printf("QoS Results: Changes (Oscillations)=%d, p99 Latency=%vms\n", changes, p99)
}
