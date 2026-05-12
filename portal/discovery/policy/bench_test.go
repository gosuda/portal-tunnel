package policy

import (
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/mols"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func BenchmarkSelectPriority(b *testing.B) {
	localAddr := "test-client-address"
	relays := make([]discovery.RelayState, 100)
	for i := 0; i < 100; i++ {
		relays[i] = discovery.RelayState{
			Descriptor:     types.RelayDescriptor{APIHTTPSAddr: "test"},
			DiscoveryRTT:   100 * time.Millisecond,
			DiscoveryRTTAt: time.Now(),
			Confirmed:      true,
		}
	}

	p := NewMOLSRelayPolicy(mols.DefaultConfig(), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.SelectPriority(relays, discovery.ClientState{LocalAddress: localAddr})
	}
}
