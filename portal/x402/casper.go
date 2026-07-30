package x402

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cockroachdb/apd/v3"
	facilitatorclient "github.com/gosuda/x402-facilitator/api/client"
	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	CasperMainnetNetwork = "casper:casper"
	CasperTestnetNetwork = "casper:casper-test"

	// DefaultCasperFacilitatorURL is the hosted x402 facilitator used when a
	// Casper payment does not configure its own endpoint.
	DefaultCasperFacilitatorURL = "https://x402-facilitator.cspr.cloud"

	// csprDecimals is the motes precision shared by CSPR and the wCSPR CEP-18 token.
	csprDecimals = 9
)

var casperNetworkDisplayNames = map[string]string{
	CasperMainnetNetwork: "Casper Mainnet",
	CasperTestnetNetwork: "Casper Testnet",
}

// CasperNetwork returns the CAIP-2 Casper network for a mainnet/testnet choice.
func CasperNetwork(testnet bool) string {
	if testnet {
		return CasperTestnetNetwork
	}
	return CasperMainnetNetwork
}

// IsCasperNetwork reports whether network is a Casper CAIP-2 identifier.
func IsCasperNetwork(network string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "casper:")
}

// NormalizeCasperAddress canonicalizes a Casper account hash or public key.
func NormalizeCasperAddress(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(address, "account-hash-"); ok {
		return "account-hash-" + rest
	}
	return address
}

// CSPRAmountToAtomic converts a human wCSPR amount, such as "0.01", to motes
// for the x402 facilitator. CSPR and wCSPR both have 9 decimals.
func CSPRAmountToAtomic(amount string) (string, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return "", errors.New("x402 wCSPR payment amount is required")
	}
	d, _, err := new(apd.Decimal).SetString(amount)
	if err != nil {
		return "", fmt.Errorf("x402 wCSPR payment amount must be a decimal CSPR amount: %s", amount)
	}
	d.Exponent += int32(csprDecimals)
	d.Reduce(d)
	if d.Form != apd.Finite || d.Sign() <= 0 {
		return "", fmt.Errorf("x402 wCSPR payment amount must be positive: %s", amount)
	}
	if d.Exponent < 0 {
		return "", fmt.Errorf("x402 wCSPR payment amount supports up to %d decimals: %s", csprDecimals, amount)
	}
	return fmt.Sprintf("%f", d), nil
}

// FormatCSPRAtomicAmount renders a motes amount as a human wCSPR amount.
func FormatCSPRAtomicAmount(amount string) string {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return ""
	}
	d, _, err := new(apd.Decimal).SetString(amount)
	if err != nil {
		return amount + " motes"
	}
	d.Exponent -= int32(csprDecimals)
	d.Reduce(d)
	if d.Form != apd.Finite || d.Sign() < 0 {
		return amount + " motes"
	}
	return fmt.Sprintf("%f wCSPR", d)
}

var _ facilitatorcore.Facilitator = (*casperFacilitator)(nil)

// casperFacilitator verifies and settles Casper payments through a remote x402
// facilitator. Casper has no Go chain SDK, so verify/settle are delegated over
// HTTP the same way any hosted x402 facilitator is used.
type casperFacilitator struct {
	network string
	client  *facilitatorclient.Client
}

func newCasperFacilitator(network string, endpoints ...string) (facilitatorcore.Facilitator, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = CasperMainnetNetwork
	}
	if _, ok := casperNetworkDisplayNames[network]; !ok {
		return nil, fmt.Errorf("unsupported Casper network %q", network)
	}
	url := DefaultCasperFacilitatorURL
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			url = endpoint
			break
		}
	}
	client, err := facilitatorclient.NewClient(url)
	if err != nil {
		return nil, fmt.Errorf("create casper x402 facilitator: %w", err)
	}
	return &casperFacilitator{network: network, client: client}, nil
}

func (f *casperFacilitator) Verify(ctx context.Context, payment *facilitatortypes.PaymentPayload, req *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentVerifyResponse, error) {
	if payment == nil || req == nil {
		return nil, errors.New("casper x402 verify requires a payment payload and requirements")
	}
	return f.client.Verify(ctx, payment, req)
}

func (f *casperFacilitator) Settle(ctx context.Context, payment *facilitatortypes.PaymentPayload, req *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentSettleResponse, error) {
	if payment == nil || req == nil {
		return nil, errors.New("casper x402 settle requires a payment payload and requirements")
	}
	return f.client.Settle(ctx, payment, req)
}

func (f *casperFacilitator) Supported() *facilitatortypes.SupportedResponse {
	return &facilitatortypes.SupportedResponse{
		Kinds: []facilitatortypes.SupportedKind{{
			X402Version: int(facilitatortypes.X402VersionV2),
			Scheme:      string(facilitatortypes.Exact),
			Network:     f.network,
		}},
		Extensions: []string{},
		Signers:    map[string][]string{},
	}
}

// NewCasperPayment builds a wCSPR x402 payment contract settled by a Casper
// x402 facilitator. The wCSPR CEP-18 contract hash must be configured through
// payment.Asset because it differs per network deployment.
func NewCasperPayment(payment types.X402Payment) (*Payment, error) {
	network := strings.TrimSpace(payment.Network)
	if network == "" {
		network = CasperNetwork(payment.Testnet)
	}
	network = strings.ToLower(network)
	if _, ok := casperNetworkDisplayNames[network]; !ok {
		return nil, fmt.Errorf("unsupported Casper network %q", network)
	}
	asset := strings.ToLower(strings.TrimSpace(payment.Asset))
	if asset == "" {
		return nil, errors.New("x402 wCSPR payment requires the wCSPR CEP-18 contract hash")
	}
	payTo := NormalizeCasperAddress(payment.PayTo)
	if payTo == "" {
		return nil, errors.New("x402 wCSPR payment requires a Casper pay-to address")
	}
	amount, err := CSPRAmountToAtomic(payment.Amount)
	if err != nil {
		return nil, err
	}
	maxTimeoutSeconds := payment.MaxTimeoutSeconds
	if maxTimeoutSeconds <= 0 {
		maxTimeoutSeconds = defaultMaxTimeoutSeconds
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            amount,
		PayTo:             payTo,
		MaxTimeoutSeconds: maxTimeoutSeconds,
		Extra: map[string]interface{}{
			"asset":               "wCSPR",
			"assetTransferMethod": "casper-cep18-transfer",
			"decimals":            csprDecimals,
		},
	}
	endpoints := append([]string(nil), payment.Endpoints...)
	facilitator, err := newCasperFacilitator(requirements.Network, endpoints...)
	if err != nil {
		return nil, err
	}

	payment.Testnet = strings.EqualFold(requirements.Network, CasperTestnetNetwork)
	payment.Network = requirements.Network
	payment.NetworkName = casperNetworkDisplayNames[requirements.Network]
	payment.Asset = requirements.Asset
	payment.PayTo = requirements.PayTo
	payment.Amount = requirements.Amount
	payment.MaxTimeoutSeconds = requirements.MaxTimeoutSeconds
	payment.Endpoints = endpoints
	payment.ResourcePath = strings.TrimSpace(payment.ResourcePath)
	payment.ResourceDescription = strings.TrimSpace(payment.ResourceDescription)
	payment.ResourceMimeType = strings.TrimSpace(payment.ResourceMimeType)

	return &Payment{
		payment:      payment,
		facilitator:  facilitator,
		requirements: requirements,
	}, nil
}
