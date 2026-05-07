package main

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestStressScenarioMessyGrid validates relay selection under high fragmentation
// (53 nodes) and intermittent RTT spikes, tracking priority oscillations.
func TestStressScenarioMessyGrid(t *testing.T) {
	const clients = 500
	const numRelays = 53

	relayStates := make([]discovery.RelayState, numRelays)
	for i := range relayStates {
		relayStates[i] = discovery.RelayState{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: fmt.Sprintf("https://test-relay-%d.example", i),
			},
		}
		for j := 0; j < 100; j++ {
			relayStates[i].UpdateEWMARTT(100 * time.Millisecond)
		}
	}

	policy := discovery.MOLSRelayPolicy{}
	var lastTop string
	oscillations := 0

	for step := 0; step < 1440; step++ {
		for i := 0; i < numRelays; i++ {
			if rand.Float64() < 0.3 {
				relayStates[i].UpdateEWMARTT(900 * time.Millisecond)
			} else {
				relayStates[i].UpdateEWMARTT(100 * time.Millisecond)
			}
		}

		cs := discovery.ClientState{
			LocalAddress: fmt.Sprintf("client-%d", rand.Intn(clients)),
		}
		result, _ := policy.SelectPriorityWithTrace(relayStates, cs)
		if len(result) > 0 {
			if lastTop != "" && result[0] != lastTop {
				oscillations++
			}
			lastTop = result[0]
		}
	}
	fmt.Printf("Messy Grid Test: Total oscillations=%d\n", oscillations)
}

// TestStressScenarioMassiveScale validates performance and stability under
// 256-node relay density.
func TestStressScenarioMassiveScale(t *testing.T) {
	const clients = 2000
	const numRelays = 256

	relayStates := make([]discovery.RelayState, numRelays)
	for i := range relayStates {
		relayStates[i] = discovery.RelayState{
			Descriptor: types.RelayDescriptor{
				APIHTTPSAddr: fmt.Sprintf("https://test-relay-%d.example", i),
			},
		}
		for j := 0; j < 100; j++ {
			relayStates[i].UpdateEWMARTT(100 * time.Millisecond)
		}
	}

	policy := discovery.MOLSRelayPolicy{}
	start := time.Now()

	for i := 0; i < clients; i++ {
		cs := discovery.ClientState{
			LocalAddress: fmt.Sprintf("client-%d", i),
		}
		_, _ = policy.SelectPriorityWithTrace(relayStates, cs)
	}

	duration := time.Since(start)
	avg := duration / time.Duration(clients)

	fmt.Printf("Massive Scale Test: Avg selection time: %v\n", avg)
	if avg > 5*time.Millisecond {
		t.Errorf("Massive Scale Test: average selection time %v exceeds limit 5ms", avg)
	}
}
