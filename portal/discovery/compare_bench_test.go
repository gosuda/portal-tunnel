package discovery

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func BenchmarkRankRelayPool(b *testing.B) {
	localAddr := "test-client-address"
	relays := make([]RelayState, 100)
	for i := 0; i < 100; i++ {
		relays[i] = RelayState{
			Descriptor:     types.RelayDescriptor{APIHTTPSAddr: "test"},
			DiscoveryRTT:   100 * time.Millisecond,
			DiscoveryRTTAt: time.Now(),
			Confirmed:      true,
		}
		// Add some dummy history
		for j := 0; j < 50; j++ {
		}
	}

	policy := MOLSRelayPolicy{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.rankRelayPool(relays, localAddr)
	}
}
