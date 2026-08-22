package x402

import (
	"strings"
	"sync"
)

// consumedSettlements is intentionally process-local. Restarting Portal clears
// the set; settlement finality remains the facilitator's responsibility.
var consumedSettlements sync.Map

func consumeSettlement(network, transaction string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	transaction = strings.TrimSpace(transaction)
	if network == "" || transaction == "" {
		return false
	}
	_, loaded := consumedSettlements.LoadOrStore(network+"\x00"+transaction, struct{}{})
	return !loaded
}
