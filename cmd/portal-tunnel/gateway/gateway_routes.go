package gateway

import (
	"fmt"
	"slices"
	"strings"

	x402http "github.com/gosuda/x402-facilitator/resource/http"
	casperscheme "github.com/gosuda/x402-facilitator/scheme/casper"
	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
	nanofacilitator "github.com/gosuda/x402-facilitator/scheme/nano/facilitator"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	suihttp "github.com/gosuda/x402-facilitator/scheme/sui/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
)

func composePaidRoute(prefix, amount string, contract X402Config, nano **nanofacilitator.NanoFacilitator) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	switch {
	case network == "" || network == suiMainnetNetwork || network == suiTestnetNetwork:
		return composeSuiRoute(prefix, amount, contract)
	case casperscheme.IsCasperNetwork(network):
		return composeCasperRoute(prefix, amount, contract)
	case nanoscheme.IsNanoNetwork(network):
		return composeNanoRoute(prefix, amount, network, contract, nano)
	default:
		return nil, fmt.Errorf("unsupported x402 network %q", network)
	}
}

func suiPaymentRequirements(network, asset, atomic, payTo string) facilitatortypes.PaymentRequirements {
	return facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            atomic,
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               "USDC",
			"assetTransferMethod": "sui-gasless-stablecoin-address-balance",
		},
	}
}

func newSuiPaymentGate(requirements facilitatortypes.PaymentRequirements, prefix string, contract X402Config) (*x402http.Gate, *suihttp.Preparer, error) {
	facilitator, err := suifacilitator.NewSuiFacilitatorWithOptions(requirements.Network, firstEndpoint(contract.Endpoints), "", suifacilitator.SuiFacilitatorOptions{
		GaslessStablecoinTypes: []string{requirements.Asset},
	})
	if err != nil {
		return nil, nil, err
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource: &facilitatortypes.ResourceInfo{
			URL:      prefix,
			MimeType: "text/html",
		},
	})
	if err != nil {
		return nil, nil, err
	}
	preparer, err := suihttp.NewPreparer(suihttp.Config{
		Requirements:     requirements,
		ResourcePath:     prefix,
		ResourceMimeType: "text/html",
		Endpoints:        contract.Endpoints,
	})
	if err != nil {
		return nil, nil, err
	}
	return gate, preparer, nil
}

func composeSuiRoute(prefix, amount string, contract X402Config) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	if network == "" {
		if contract.Testnet {
			network = suiTestnetNetwork
		} else {
			network = suiMainnetNetwork
		}
	}
	asset, ok := suischeme.GetGaslessStablecoinType(network, "USDC")
	if !ok {
		return nil, fmt.Errorf("USDC is not gasless stablecoin allowlisted on %s", network)
	}
	payTo := suischeme.NormalizeAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402UsdcPaymentRequiresSuiPay
	}
	atomic, err := suischeme.StablecoinAmountToAtomic(network, "USDC", amount)
	if err != nil {
		return nil, err
	}
	requirements := suiPaymentRequirements(network, asset, atomic, payTo)
	gate, preparer, err := newSuiPaymentGate(requirements, prefix, contract)
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate, preparer: preparer}, nil
}

func composeCasperRoute(prefix, amount string, contract X402Config) (*routePolicy, error) {
	network := strings.ToLower(strings.TrimSpace(contract.Network))
	if network == "" {
		if contract.Testnet {
			network = casperscheme.NetworkTestnet
		} else {
			network = casperscheme.NetworkMainnet
		}
	}
	if casperscheme.GetNetworkInfo(network) == nil {
		return nil, fmt.Errorf("unsupported Casper network %q", network)
	}
	asset := strings.ToLower(strings.TrimSpace(contract.Asset))
	if asset == "" {
		return nil, errX402WcsprPaymentRequiresWcsprCep
	}
	payTo := casperscheme.NormalizeAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402WcsprPaymentRequiresCasperPay
	}
	motes, err := casperscheme.CSPRToMotes(amount)
	if err != nil {
		return nil, err
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            motes.String(),
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               casperscheme.WCSPRSymbol,
			"assetTransferMethod": "casper-cep18-transfer",
			"decimals":            casperscheme.MoteDecimals,
		},
	}
	gate, err := newComposeCasperRouteGate(prefix, requirements, contract)
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate}, nil
}

func newComposeCasperRouteGate(prefix string, requirements facilitatortypes.PaymentRequirements, contract X402Config) (*x402http.Gate, error) {
	facilitator, err := newCasperFacilitatorClient(contract)
	if err != nil {
		return nil, err
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource:     &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
	})
	if err != nil {
		return nil, err
	}
	return gate, nil
}

func resolveNanoFacilitator(network string, contract X402Config, nano **nanofacilitator.NanoFacilitator) error {
	if *nano != nil {
		return nil
	}
	endpoints := make([]string, 0, len(contract.Endpoints))
	for _, endpoint := range contract.Endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" && !slices.Contains(endpoints, endpoint) {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) > 0 && len(endpoints) < nanoscheme.MinIndependentEndpoints {
		return fmt.Errorf("x402 XNO payment requires at least %d independent Nano RPC endpoints", nanoscheme.MinIndependentEndpoints)
	}
	facilitator, err := nanofacilitator.NewNanoFacilitatorWithOptions(network, "", "", nanofacilitator.NanoFacilitatorOptions{
		Endpoints: endpoints,
	})
	if err != nil {
		return err
	}
	*nano = facilitator
	return nil
}

func composeNanoRoute(prefix, amount, network string, contract X402Config, nano **nanofacilitator.NanoFacilitator) (*routePolicy, error) {
	payTo := normalizeNanoAddress(contract.PayTo)
	if payTo == "" {
		return nil, errX402XnoPaymentRequiresChecksummedNano
	}
	raw, err := xnoToRaw(amount)
	if err != nil {
		return nil, err
	}
	if err := resolveNanoFacilitator(network, contract, nano); err != nil {
		return nil, err
	}
	requirements := buildComposeNanoRouteRequirements(network, payTo, raw)
	gate, err := newComposeNanoRouteGate(prefix, requirements, *nano)
	if err != nil {
		return nil, err
	}
	return &routePolicy{requirements: canonicalRequirements(requirements), gate: gate}, nil
}

func buildComposeNanoRouteRequirements(network, payTo, raw string) facilitatortypes.PaymentRequirements {
	return facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             nanoscheme.AssetXNO,
		Amount:            raw,
		PayTo:             payTo,
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               nanoscheme.AssetXNO,
			"assetTransferMethod": "nano-native-send",
			"decimals":            nanoscheme.XNORawDecimals,
		},
	}
}

func newComposeNanoRouteGate(prefix string, requirements facilitatortypes.PaymentRequirements, facilitator *nanofacilitator.NanoFacilitator) (*x402http.Gate, error) {
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource:     &facilitatortypes.ResourceInfo{URL: prefix, MimeType: "text/html"},
	})
	if err != nil {
		return nil, err
	}
	return gate, nil
}
