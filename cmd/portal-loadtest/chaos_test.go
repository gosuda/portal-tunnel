package main

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestChaosMeshScenario(t *testing.T) {
	// Extreme Chaos Mesh: 100 relays, constant churn, massive RTT swings
	const numRelays = 100
	const rounds = 2000

	relayStates := make([]discovery.RelayState, numRelays)
	for i := range relayStates {
		relayStates[i] = discovery.RelayState{
			Descriptor: types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("node-%d", i)},
		}
	}

	policy := discovery.MOLSRelayPolicy{}
	var history []string
	var latencies []time.Duration
	errors := 0

	start := time.Now()
	for r := 0; r < rounds; r++ {
		// Random Churn: Add/Remove relays
		for i := 0; i < numRelays; i++ {
			if rand.Float64() < 0.05 { // 5% churn per round
				relayStates[i].DiscoveryRTT = time.Duration(100+rand.Intn(900)) * time.Millisecond
			}
		}

		cs := discovery.ClientState{LocalAddress: "chaos-client"}
		res, _ := policy.SelectPriorityWithTrace(relayStates, cs)

		if len(res) == 0 {
			errors++
		} else {
			history = append(history, res[0])
			latencies = append(latencies, 100*time.Millisecond) // Mock
		}
	}

	m := CalculateMetrics(history, latencies, errors, rounds, time.Since(start))
	fmt.Printf("Chaos Mesh Metrics: %+v\n", m)
}
