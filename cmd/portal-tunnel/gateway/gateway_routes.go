package gateway

import (
	"github.com/gosuda/x402-facilitator/resource/paywall"
)

func (c X402Config) paywallConfig() paywall.Config {
	return paywall.Config{
		Network:          c.Network,
		Testnet:          c.Testnet,
		Asset:            c.Asset,
		PayTo:            c.PayTo,
		Endpoints:        c.Endpoints,
		FacilitatorToken: c.FacilitatorToken,
		Options:          c.Options,
	}
}
