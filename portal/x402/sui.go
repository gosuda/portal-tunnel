package x402

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	foundationx402 "github.com/x402-foundation/x402/go"
	x402types "github.com/x402-foundation/x402/go/types"

	portaltypes "github.com/gosuda/portal-tunnel/v2/types"
)

type suiExactServer struct{}

func newSuiExactServer(network string) (*suiExactServer, error) {
	network = strings.TrimSpace(strings.ToLower(network))
	if suischeme.GetNetworkInfo(network) == nil {
		return nil, fmt.Errorf("unsupported Sui network %q", network)
	}
	return &suiExactServer{}, nil
}

func (s *suiExactServer) Scheme() string {
	return portaltypes.X402SchemeExact
}

func (s *suiExactServer) GetAssetDecimals(asset string, network foundationx402.Network) int {
	decimals, ok := suischeme.GetGaslessStablecoinDecimals(strings.TrimSpace(strings.ToLower(string(network))), asset)
	if !ok {
		return 6
	}
	return int(decimals)
}

func (s *suiExactServer) ParsePrice(price foundationx402.Price, network foundationx402.Network) (foundationx402.AssetAmount, error) {
	networkID := strings.TrimSpace(strings.ToLower(string(network)))
	if amount, ok := price.(foundationx402.AssetAmount); ok {
		return s.normalizeAssetAmount(amount, networkID)
	}
	if priceMap, ok := price.(map[string]interface{}); ok {
		amountValue, ok := priceMap["amount"]
		if !ok {
			return foundationx402.AssetAmount{}, errors.New("sui payment price amount is required")
		}
		amount, ok := amountValue.(string)
		if !ok {
			return foundationx402.AssetAmount{}, errors.New("sui payment price amount must be a string")
		}
		asset, _ := priceMap["asset"].(string)
		if strings.TrimSpace(asset) == "" {
			asset = defaultSuiStablecoinAsset(networkID)
		}
		var extra map[string]interface{}
		if extraValue, ok := priceMap["extra"].(map[string]interface{}); ok {
			extra = extraValue
		}
		return s.normalizeAssetAmount(foundationx402.AssetAmount{
			Asset:  asset,
			Amount: amount,
			Extra:  extra,
		}, networkID)
	}

	asset := defaultSuiStablecoinAsset(networkID)
	amount, err := parseSuiDisplayPriceToAtomic(price, s.GetAssetDecimals(asset, network))
	if err != nil {
		return foundationx402.AssetAmount{}, err
	}
	return s.normalizeAssetAmount(foundationx402.AssetAmount{
		Asset:  asset,
		Amount: amount,
	}, networkID)
}

func (s *suiExactServer) EnhancePaymentRequirements(
	ctx context.Context,
	requirements x402types.PaymentRequirements,
	supportedKind x402types.SupportedKind,
	extensionKeys []string,
) (x402types.PaymentRequirements, error) {
	_ = ctx
	_ = extensionKeys

	network := strings.TrimSpace(strings.ToLower(requirements.Network))
	if network == "" {
		return requirements, errors.New("sui payment rail is required")
	}
	requirements.Network = network
	if requirements.Asset == "" {
		requirements.Asset = defaultSuiStablecoinAsset(network)
	} else {
		requirements.Asset = normalizeSuiAsset(network, requirements.Asset)
	}
	if strings.Contains(requirements.Amount, ".") || strings.HasPrefix(strings.TrimSpace(requirements.Amount), "$") {
		amount, err := resolveSuiDisplayAmount(requirements.Amount, s.GetAssetDecimals(requirements.Asset, foundationx402.Network(network)))
		if err != nil {
			return requirements, err
		}
		requirements.Amount = amount
	}
	payTo := suischeme.NormalizeAddress(requirements.PayTo)
	if payTo == "" {
		return requirements, errors.New("sui receive address must be valid")
	}
	requirements.PayTo = payTo

	if requirements.Extra == nil {
		requirements.Extra = make(map[string]interface{})
	}
	if supportedKind.Extra != nil {
		for key, value := range supportedKind.Extra {
			requirements.Extra[key] = value
		}
	}
	return requirements, nil
}

func (s *suiExactServer) normalizeAssetAmount(amount foundationx402.AssetAmount, network string) (foundationx402.AssetAmount, error) {
	amount.Asset = normalizeSuiAsset(network, amount.Asset)
	if strings.TrimSpace(amount.Asset) == "" {
		return foundationx402.AssetAmount{}, errors.New("sui payment asset is required")
	}
	if strings.TrimSpace(amount.Amount) == "" {
		return foundationx402.AssetAmount{}, errors.New("sui payment amount is required")
	}
	return amount, nil
}

func defaultSuiStablecoinAsset(network string) string {
	if asset, ok := suischeme.GetGaslessStablecoinType(strings.TrimSpace(strings.ToLower(network)), "USDC"); ok {
		return asset
	}
	return suischeme.USDCType
}

func normalizeSuiAsset(network, asset string) string {
	asset = strings.TrimSpace(asset)
	if asset == "" {
		return ""
	}
	if coinType, ok := suischeme.GetGaslessStablecoinType(strings.TrimSpace(strings.ToLower(network)), asset); ok {
		return coinType
	}
	return asset
}

func parseSuiDisplayPriceToAtomic(price foundationx402.Price, decimals int) (string, error) {
	switch value := price.(type) {
	case string:
		return resolveSuiDisplayAmount(value, decimals)
	case float64:
		return resolveSuiDisplayAmount(strconv.FormatFloat(value, 'f', decimals, 64), decimals)
	case int:
		return resolveSuiDisplayAmount(strconv.Itoa(value), decimals)
	case int64:
		return resolveSuiDisplayAmount(strconv.FormatInt(value, 10), decimals)
	default:
		return "", fmt.Errorf("unsupported Sui payment price type: %T", price)
	}
}

func resolveSuiDisplayAmount(raw string, decimals int) (string, error) {
	literal, err := normalizeSuiDisplayAmountLiteral(raw, decimals)
	if err != nil {
		return "", err
	}
	resolved, err := foundationx402.ResolveSettlementOverrideAmount("$"+literal, x402types.PaymentRequirements{}, decimals)
	if err != nil {
		return "", err
	}
	amount, ok := new(big.Int).SetString(resolved, 10)
	if !ok {
		return "", fmt.Errorf("invalid Sui payment price: %s", raw)
	}
	if amount.Sign() <= 0 {
		return "", errors.New("sui payment price must be positive")
	}
	return amount.String(), nil
}

func normalizeSuiDisplayAmountLiteral(raw string, decimals int) (string, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "$")
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("sui payment price is required")
	}
	if strings.HasPrefix(value, "-") {
		return "", errors.New("sui payment price cannot be negative")
	}
	value = strings.TrimPrefix(value, "+")
	if strings.HasPrefix(value, ".") {
		value = "0" + value
	}
	value = strings.TrimSuffix(value, ".")
	whole, fractional, ok := strings.Cut(value, ".")
	if !ok {
		fractional = ""
	}
	if whole == "" {
		whole = "0"
	}
	if !decimalDigits(whole) || !decimalDigits(fractional) {
		return "", fmt.Errorf("invalid Sui payment price: %s", raw)
	}
	if len(fractional) > decimals {
		if strings.Trim(fractional[decimals:], "0") != "" {
			return "", fmt.Errorf("sui payment price has more than %d decimal places: %s", decimals, raw)
		}
	}
	if fractional == "" {
		return whole, nil
	}
	return whole + "." + fractional, nil
}

func decimalDigits(value string) bool {
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
