package types

// x402 payment requirement metadata advertised to clients in a 402
// challenge. The sui gasless values mirror the x402-facilitator sui scheme's
// settlement method, which does not export them.
const (
	X402USDCSymbol               = "USDC"
	X402SuiGaslessTransferMethod = "sui-gasless-stablecoin-address-balance"
)

// X402SuiGaslessExtra returns the payment requirement Extra metadata for a
// sui gasless USDC settlement: the shape clients read from a 402 challenge.
func X402SuiGaslessExtra() map[string]any {
	return map[string]any{
		"asset":               X402USDCSymbol,
		"assetTransferMethod": X402SuiGaslessTransferMethod,
	}
}
