package x402

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type settlementFacilitator struct {
	transaction string
	network     facilitatortypes.Network
}

func (f *settlementFacilitator) Verify(_ context.Context, _ *facilitatortypes.PaymentPayload, _ *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentVerifyResponse, error) {
	return &facilitatortypes.PaymentVerifyResponse{IsValid: true}, nil
}

func (f *settlementFacilitator) Settle(_ context.Context, _ *facilitatortypes.PaymentPayload, _ *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentSettleResponse, error) {
	network := f.network
	if strings.TrimSpace(string(network)) == "" {
		network = "sui:mainnet"
	}
	return &facilitatortypes.PaymentSettleResponse{
		Success:     true,
		Network:     network,
		Transaction: f.transaction,
	}, nil
}

func (f *settlementFacilitator) Supported() *facilitatortypes.SupportedResponse {
	return &facilitatortypes.SupportedResponse{}
}

var _ facilitatorcore.Facilitator = (*settlementFacilitator)(nil)

func paidRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/paid", nil)
	req.Header.Set(types.HeaderXPayment, `{"scheme":"exact"}`)
	return req
}

func TestSettleRejectsEmptyTransactionDigest(t *testing.T) {
	payment := &Payment{
		facilitator:  &settlementFacilitator{transaction: "  "},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}

	recorder := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), recorder, paidRequest()); ok {
		t.Fatal("a settlement without a transaction digest must be rejected")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("empty-digest settlement status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "missing transaction digest") {
		t.Fatalf("empty-digest settlement body = %q, want missing-digest reason", body)
	}
}

func TestSettleRejectsFacilitatorNetworkMismatch(t *testing.T) {
	payment := &Payment{
		facilitator: &settlementFacilitator{
			transaction: "digest-wrong-network",
			network:     "sui:testnet",
		},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}

	recorder := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), recorder, paidRequest()); ok {
		t.Fatal("a settlement for a different network must be rejected")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("network-mismatch status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "network mismatch") {
		t.Fatalf("network-mismatch body = %q, want mismatch reason", body)
	}
}

func TestSettleAcceptsNormalizedFacilitatorNetwork(t *testing.T) {
	payment := &Payment{
		facilitator: &settlementFacilitator{
			transaction: "digest-normalized-network",
			network:     " SUI:MAINNET ",
		},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}

	if _, ok := payment.Settle(context.Background(), httptest.NewRecorder(), paidRequest()); !ok {
		t.Fatal("network comparison should ignore surrounding whitespace and casing")
	}
}

func TestSettleRejectsConsumedTransaction(t *testing.T) {
	const transaction = "digest-consumed-transaction"
	first := &Payment{
		facilitator:  &settlementFacilitator{transaction: transaction},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}
	second := &Payment{
		facilitator:  &settlementFacilitator{transaction: transaction, network: "SUI:MAINNET"},
		requirements: facilitatortypes.PaymentRequirements{Network: "sui:mainnet"},
	}

	if _, ok := first.Settle(context.Background(), httptest.NewRecorder(), paidRequest()); !ok {
		t.Fatal("the first settlement must grant access")
	}
	recorder := httptest.NewRecorder()
	if _, ok := second.Settle(context.Background(), recorder, paidRequest()); ok {
		t.Fatal("the same transaction must not grant access twice in one process")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("consumed settlement status = %d, want %d", recorder.Code, http.StatusPaymentRequired)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "already redeemed") {
		t.Fatalf("consumed settlement body = %q, want already-redeemed reason", body)
	}
}
