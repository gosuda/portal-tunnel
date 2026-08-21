package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cockroachdb/apd/v3"
	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const usdcDecimals = 6

// Payment owns one x402 payment contract and its facilitator runtime.
type Payment struct {
	payment      types.X402Payment
	facilitator  facilitatorcore.Facilitator
	requirements facilitatortypes.PaymentRequirements
	spent        *SpentDigests
}

// NewPayment builds the payment implementation selected by its CAIP-2
// network. An empty network preserves the existing Sui mainnet/testnet
// selection. The payment gets its own spent-digest store, persisted when the
// contract configures a ledger path; resource servers serving several paid
// routes must share one store via NewPaymentWithSpent.
func NewPayment(payment types.X402Payment) (*Payment, error) {
	return newPayment(payment, nil)
}

// NewPaymentWithSpent builds a payment bound to a caller-owned spent-digest
// store so every paid route of one HTTP surface enforces globally single-use
// settlements.
func NewPaymentWithSpent(payment types.X402Payment, spent *SpentDigests) (*Payment, error) {
	if spent == nil {
		return nil, errors.New("x402 payment requires a spent-digest store")
	}
	return newPayment(payment, spent)
}

func newPayment(payment types.X402Payment, spent *SpentDigests) (*Payment, error) {
	network := strings.ToLower(strings.TrimSpace(payment.Network))
	usdc := network == "" || network == MainnetNetwork || network == TestnetNetwork
	if !usdc && !IsCasperNetwork(network) {
		return nil, fmt.Errorf("unsupported x402 network %q", network)
	}
	if spent == nil {
		store, err := NewSpentDigests(payment.SpentLedgerPath)
		if err != nil {
			return nil, fmt.Errorf("x402 spent-payment ledger: %w", err)
		}
		spent = store
	}
	if usdc {
		return newUSDCPayment(payment, spent)
	}
	return newCasperPayment(payment, spent)
}

// NewUSDCPayment builds a Sui USDC payment contract with its own spent-digest
// store, persisted when the contract configures a ledger path.
func NewUSDCPayment(payment types.X402Payment) (*Payment, error) {
	store, err := NewSpentDigests(payment.SpentLedgerPath)
	if err != nil {
		return nil, fmt.Errorf("x402 spent-payment ledger: %w", err)
	}
	return newUSDCPayment(payment, store)
}

func newUSDCPayment(payment types.X402Payment, spent *SpentDigests) (*Payment, error) {
	network := strings.TrimSpace(payment.Network)
	if network == "" {
		network = Network(payment.Testnet)
	}
	network = strings.ToLower(network)
	asset, err := usdcAsset(network)
	if err != nil {
		return nil, err
	}
	payTo := suischeme.NormalizeAddress(payment.PayTo)
	if payTo == "" {
		return nil, errors.New("x402 USDC payment requires a Sui pay-to address")
	}
	amount, err := USDCAmountToAtomic(payment.Amount)
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
			"asset":               "USDC",
			"assetTransferMethod": "sui-gasless-stablecoin-address-balance",
		},
	}
	endpoints := append([]string(nil), payment.Endpoints...)
	facilitator, err := newUSDCFacilitator(requirements.Network, requirements.Asset, endpoints...)
	if err != nil {
		return nil, err
	}
	networkName := NetworkDisplayName(requirements.Network)
	if networkName == "" {
		networkName = requirements.Network
	}
	payment.Testnet = strings.EqualFold(requirements.Network, TestnetNetwork)
	payment.Network = requirements.Network
	payment.NetworkName = networkName
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
		spent:        spent,
	}, nil
}

// USDCAmountToAtomic converts a human USDC amount, such as "0.01", to atomic
// units for the x402 facilitator. USDC has 6 decimals.
func USDCAmountToAtomic(amount string) (string, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return "", errors.New("x402 USDC payment amount is required")
	}
	d, _, err := new(apd.Decimal).SetString(amount)
	if err != nil {
		return "", fmt.Errorf("x402 USDC payment amount must be a decimal USDC amount: %s", amount)
	}
	d.Exponent += int32(usdcDecimals)
	d.Reduce(d)
	if d.Form != apd.Finite || d.Sign() <= 0 {
		return "", fmt.Errorf("x402 USDC payment amount must be positive: %s", amount)
	}
	if d.Exponent < 0 {
		return "", fmt.Errorf("x402 USDC payment amount supports up to %d decimals: %s", usdcDecimals, amount)
	}
	return fmt.Sprintf("%f", d), nil
}

// FormatUSDCAtomicAmount renders an atomic USDC amount as a human amount.
func FormatUSDCAtomicAmount(amount string) string {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return ""
	}
	d, _, err := new(apd.Decimal).SetString(amount)
	if err != nil {
		return amount + " atomic USDC"
	}
	d.Exponent -= int32(usdcDecimals)
	d.Reduce(d)
	if d.Form != apd.Finite || d.Sign() < 0 {
		return amount + " atomic USDC"
	}
	return fmt.Sprintf("%f USDC", d)
}

func (p *Payment) paymentPayloadFromRequest(w http.ResponseWriter, r *http.Request) (*facilitatortypes.PaymentPayload, bool) {
	if p == nil {
		http.Error(w, "payment is not configured", http.StatusInternalServerError)
		return nil, false
	}

	rawPayment := ""
	for _, name := range []string{types.HeaderXPayment, types.HeaderPaymentSignature} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			rawPayment = value
			break
		}
	}
	if rawPayment == "" {
		p.writePaymentRequired(w, r, "payment required", "")
		return nil, false
	}

	var payload *facilitatortypes.PaymentPayload
	var decoded facilitatortypes.PaymentPayload
	if err := json.Unmarshal([]byte(rawPayment), &decoded); err == nil {
		payload = &decoded
	}
	if payload == nil {
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			raw, err := encoding.DecodeString(rawPayment)
			if err != nil {
				continue
			}
			var decoded facilitatortypes.PaymentPayload
			if err := json.Unmarshal(raw, &decoded); err == nil {
				payload = &decoded
				break
			}
		}
	}
	if payload == nil {
		p.writePaymentRequired(w, r, "invalid payment payload", "")
		return nil, false
	}
	return payload, true
}

func (p *Payment) Settle(ctx context.Context, w http.ResponseWriter, r *http.Request) (*facilitatortypes.PaymentSettleResponse, bool) {
	if p == nil {
		http.Error(w, "payment is not configured", http.StatusInternalServerError)
		return nil, false
	}
	if p.facilitator == nil {
		http.Error(w, "x402 facilitator is not configured", http.StatusInternalServerError)
		return nil, false
	}
	payment, ok := p.paymentPayloadFromRequest(w, r)
	if !ok {
		return nil, false
	}
	settled, err := p.facilitator.Settle(ctx, payment, &p.requirements)
	if err != nil {
		log.Warn().
			Err(err).
			Str("network", p.requirements.Network).
			Str("asset", p.requirements.Asset).
			Msg("settle x402 payment")
		p.writePaymentRequired(w, r, "payment settlement failed", "")
		return nil, false
	}
	if settled == nil || !settled.Success {
		event := log.Warn().
			Str("network", p.requirements.Network).
			Str("asset", p.requirements.Asset)
		if settled != nil {
			errorMessage := strings.TrimSpace(settled.ErrorMessage)
			if errorMessage == "" {
				errorMessage = "<empty>"
			}
			event = event.
				Str("reason", strings.TrimSpace(settled.ErrorReason)).
				Str("error_message", errorMessage).
				Str("payer", strings.TrimSpace(settled.Payer)).
				Str("transaction", strings.TrimSpace(settled.Transaction))
		}
		event.Msg("x402 payment settlement rejected")
		p.writePaymentRequired(w, r, "payment settlement failed", "")
		return nil, false
	}
	digest := strings.TrimSpace(settled.Transaction)
	if digest == "" {
		log.Warn().
			Str("network", string(p.requirements.Network)).
			Msg("x402 settlement succeeded without a transaction digest")
		p.writePaymentRequired(w, r, "settlement response missing transaction digest", "")
		return nil, false
	}
	network := strings.TrimSpace(string(settled.Network))
	if network == "" {
		network = string(p.requirements.Network)
	}
	if p.spent == nil {
		p.writePaymentRequired(w, r, "payment replay tracking unavailable", "")
		return nil, false
	}
	consumed, err := p.spent.Consume(network, digest)
	if err != nil {
		p.writePaymentRequired(w, r, "payment ledger unavailable", "")
		return nil, false
	}
	if !consumed {
		log.Warn().
			Str("network", network).
			Str("transaction", digest).
			Msg("x402 payment replay rejected")
		p.writePaymentRequired(w, r, "payment already redeemed", "")
		return nil, false
	}
	return settled, true
}

func (p *Payment) writePaymentRequired(w http.ResponseWriter, r *http.Request, reason, resourcePath string) {
	if p == nil {
		http.Error(w, reason, http.StatusPaymentRequired)
		return
	}
	resourceURL := ""
	resourcePath = strings.TrimSpace(resourcePath)
	if resourcePath != "" {
		resourceURL = utils.PublicURLForPath(r, resourcePath)
	} else if r != nil && r.URL != nil {
		resourceURL = utils.PublicURLForPath(r, r.URL.RequestURI())
	}
	body := struct {
		X402Version int                                    `json:"x402Version"`
		Error       string                                 `json:"error,omitempty"`
		Resource    *facilitatortypes.ResourceInfo         `json:"resource,omitempty"`
		Accepts     []facilitatortypes.PaymentRequirements `json:"accepts"`
	}{
		X402Version: int(facilitatortypes.X402VersionV2),
		Error:       strings.TrimSpace(reason),
		Resource:    &facilitatortypes.ResourceInfo{URL: resourceURL},
		Accepts:     []facilitatortypes.PaymentRequirements{p.requirements},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode x402 payment requirements", http.StatusInternalServerError)
		return
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(types.HeaderPaymentRequired, encoded)
	w.Header().Set(types.HeaderXPaymentRequired, encoded)
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(raw)
}

func (p *Payment) WritePrepare(w http.ResponseWriter, r *http.Request, sender, resourcePath string) {
	if p == nil {
		http.Error(w, "payment is not configured", http.StatusInternalServerError)
		return
	}
	ctx := r.Context()
	cancel := func() {}
	if p.payment.RequestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, p.payment.RequestTimeout)
	}
	defer cancel()

	if IsCasperNetwork(p.requirements.Network) {
		// Casper payments are signed by the wallet against the published
		// requirements, so there is no server-built transaction to prepare.
		resourcePath = strings.TrimSpace(resourcePath)
		if resourcePath == "" {
			resourcePath = strings.TrimSpace(p.payment.ResourcePath)
		}
		p.writePaymentRequired(w, r, "payment required", resourcePath)
		return
	}

	sender = suischeme.NormalizeAddress(sender)
	if sender == "" {
		http.Error(w, "sender is required", http.StatusBadRequest)
		return
	}
	if p.requirements.Network == "" || p.requirements.Asset == "" {
		http.Error(w, "payment is not configured", http.StatusInternalServerError)
		return
	}

	coinObjects, err := suischeme.ListOwnedGaslessStablecoinCoinObjects(ctx, p.requirements.Network, sender, p.requirements.Asset, p.payment.Endpoints)
	if err != nil {
		http.Error(w, fmt.Sprintf("list USDC coin objects: %v", err), http.StatusBadGateway)
		return
	}
	nonZeroCoinObjects := make([]suischeme.OwnedCoinObject, 0, len(coinObjects))
	for _, coinObject := range coinObjects {
		if coinObject.Balance == 0 {
			continue
		}
		nonZeroCoinObjects = append(nonZeroCoinObjects, coinObject)
	}

	var prepareTransaction *struct {
		Transaction string `json:"transaction"`
	}
	if len(nonZeroCoinObjects) > 0 {
		txBytes, err := suischeme.BuildCoinObjectsToAddressBalanceTransferTransaction(ctx, suischeme.CoinObjectsToAddressBalanceTransfer{
			Sender:      sender,
			Recipient:   sender,
			Network:     p.requirements.Network,
			Asset:       p.requirements.Asset,
			CoinObjects: nonZeroCoinObjects,
			Endpoints:   p.payment.Endpoints,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("build prepare transaction: %v", err), http.StatusBadGateway)
			return
		}
		prepareTransaction = &struct {
			Transaction string `json:"transaction"`
		}{Transaction: base64.StdEncoding.EncodeToString(txBytes)}
	}

	paymentTxBytes, err := suischeme.BuildGaslessStablecoinTransferTransaction(ctx, suischeme.GaslessStablecoinTransfer{
		Sender:    sender,
		Recipient: p.requirements.PayTo,
		Network:   p.requirements.Network,
		Asset:     p.requirements.Asset,
		Amount:    p.requirements.Amount,
		Endpoints: p.payment.Endpoints,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("build payment transaction: %v", err), http.StatusBadGateway)
		return
	}

	resourcePath = strings.TrimSpace(resourcePath)
	if resourcePath == "" {
		resourcePath = strings.TrimSpace(p.payment.ResourcePath)
	}
	if resourcePath == "" && r.URL != nil {
		resourcePath = r.URL.Path
	}
	if resourcePath == "" {
		resourcePath = "/"
	}
	resourceMimeType := strings.TrimSpace(p.payment.ResourceMimeType)
	if resourceMimeType == "" {
		resourceMimeType = "text/html"
	}
	utils.WritePaymentJSON(w, http.StatusOK, types.X402PreparePaymentResponse{
		X402Version:         int(facilitatortypes.X402VersionV2),
		PaymentRequirements: p.requirements,
		Resource: &facilitatortypes.ResourceInfo{
			URL:         utils.PublicURLForPath(r, resourcePath),
			Description: strings.TrimSpace(p.payment.ResourceDescription),
			MimeType:    resourceMimeType,
		},
		PrepareTransaction: prepareTransaction,
		PaymentTransaction: struct {
			Transaction string `json:"transaction"`
		}{Transaction: base64.StdEncoding.EncodeToString(paymentTxBytes)},
	})
}
