package discovery

import (
	"fmt"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestStressScenarioMassiveScale(t *testing.T) {
	clients := 2000
	numRelays := 256
	relayStates := make([]RelayState, numRelays)
	for i := range relayStates {
		relayStates[i] = RelayState{Descriptor: types.RelayDescriptor{APIHTTPSAddr: fmt.Sprintf("https://test-%d.example", i)}}
	}
	policy := MOLSRelayPolicy{}
	start := time.Now()
	for i := 0; i < clients; i++ {
		cs := ClientState{LocalAddress: fmt.Sprintf("client-%d", i)}
		policy.SelectPriority(relayStates, cs)
	}
	fmt.Printf("Massive Scale Test: Avg selection time: %v\n", time.Since(start)/time.Duration(clients))
}
