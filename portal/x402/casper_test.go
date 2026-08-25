package x402

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const testWCSPRAsset = "hash-9c0d3fd7b1d9b5a94b13a5df0b1c8f1a0b3e5d7c9a1b3d5f7092a4c6e8b0d2f4"
const testFacilitatorToken = "test-token"

// Payment amounts are money: the decimal-to-motes conversion must be exact and
// must reject zero, negative, and sub-mote precision inputs.
func TestCSPRAmountToAtomic(t *testing.T) {
	tests := []struct {
		name    string
		amount  string
		want    string
		wantErr bool
	}{
		{name: "whole", amount: "1", want: "1000000000"},
		{name: "cents", amount: "0.01", want: "10000000"},
		{name: "one mote", amount: "0.000000001", want: "1"},
		{name: "padded", amount: " 2.5 ", want: "2500000000"},
		{name: "empty", amount: "", wantErr: true},
		{name: "not a number", amount: "abc", wantErr: true},
		{name: "zero", amount: "0", wantErr: true},
		{name: "negative", amount: "-1", wantErr: true},
		{name: "too many decimals", amount: "0.0000000001", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CSPRAmountToAtomic(tt.amount)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("CSPRAmountToAtomic(%q) = %q, want error", tt.amount, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CSPRAmountToAtomic(%q) error: %v", tt.amount, err)
			}
			if got != tt.want {
				t.Fatalf("CSPRAmountToAtomic(%q) = %q, want %q", tt.amount, got, tt.want)
			}
		})
	}
}

// The facilitator token is a server-side credential: the payment challenge a
// client receives must never disclose it, in the body or in any header.
func TestPaymentChallengeDoesNotDiscloseFacilitatorToken(t *testing.T) {
	payment, err := NewCasperPayment(types.X402Payment{
		Testnet:          true,
		Asset:            testWCSPRAsset,
		PayTo:            "Account-Hash-ABC123",
		Amount:           "0.25",
		FacilitatorToken: testFacilitatorToken,
	})
	if err != nil {
		t.Fatalf("NewCasperPayment: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil)
	rec := httptest.NewRecorder()
	if _, ok := payment.Settle(context.Background(), rec, req); ok {
		t.Fatal("Settle() without payment = ok, want challenge")
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}

	exposed := rec.Body.String()
	for name, values := range rec.Header() {
		exposed += name + ": " + strings.Join(values, ",") + "\n"
	}
	if strings.Contains(exposed, testFacilitatorToken) {
		t.Fatal("payment challenge disclosed the facilitator token")
	}
}

func TestCasperFacilitatorSettle(t *testing.T) {
	var got facilitatortypes.PaymentSettleRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/settle" {
			t.Errorf("path = %q, want /settle", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode settle request: %v", err)
		}
		if token := r.Header.Get("Authorization"); token != testFacilitatorToken {
			t.Errorf("Authorization = %q, want %q", token, testFacilitatorToken)
		}
		_ = json.NewEncoder(w).Encode(facilitatortypes.PaymentSettleResponse{
			Success:     true,
			Payer:       "01a1b2c3",
			Transaction: "5f0e1d2c",
			Network:     facilitatortypes.Network(CasperTestnetNetwork),
		})
	}))
	defer server.Close()

	payment, err := NewCasperPayment(types.X402Payment{
		Testnet:          true,
		Asset:            testWCSPRAsset,
		PayTo:            "account-hash-abc123",
		Amount:           "0.01",
		Endpoints:        []string{server.URL},
		FacilitatorToken: testFacilitatorToken,
	})
	if err != nil {
		t.Fatalf("NewCasperPayment: %v", err)
	}

	settled, err := payment.facilitator.Settle(context.Background(), &facilitatortypes.PaymentPayload{
		X402Version: int(facilitatortypes.X402VersionV2),
		Payload:     map[string]any{"signature": "deadbeef"},
		Accepted:    payment.requirements,
	}, &payment.requirements)
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if !settled.Success {
		t.Fatalf("settle success = false, error %q", settled.ErrorMessage)
	}
	if settled.Transaction != "5f0e1d2c" {
		t.Fatalf("transaction = %q, want %q", settled.Transaction, "5f0e1d2c")
	}
	if got.PaymentRequirements.Amount != "10000000" {
		t.Fatalf("settled amount = %q, want %q", got.PaymentRequirements.Amount, "10000000")
	}
	if got.PaymentRequirements.Network != CasperTestnetNetwork {
		t.Fatalf("settled network = %q, want %q", got.PaymentRequirements.Network, CasperTestnetNetwork)
	}
}

func TestCasperFacilitatorVerifyRejects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := r.Header.Get("Authorization"); token != testFacilitatorToken {
			t.Errorf("Authorization = %q, want %q", token, testFacilitatorToken)
		}
		_ = json.NewEncoder(w).Encode(facilitatortypes.PaymentVerifyResponse{
			IsValid:        false,
			InvalidReason:  "insufficient_balance",
			InvalidMessage: "payer wCSPR balance is too low",
		})
	}))
	defer server.Close()

	facilitator, err := newCasperFacilitator(CasperTestnetNetwork, testFacilitatorToken, server.URL)
	if err != nil {
		t.Fatalf("newCasperFacilitator: %v", err)
	}
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:  string(facilitatortypes.Exact),
		Network: CasperTestnetNetwork,
		Asset:   testWCSPRAsset,
		Amount:  "10000000",
		PayTo:   "account-hash-abc123",
	}
	verified, err := facilitator.Verify(context.Background(), &facilitatortypes.PaymentPayload{
		X402Version: int(facilitatortypes.X402VersionV2),
		Accepted:    requirements,
	}, &requirements)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IsValid {
		t.Fatal("verify isValid = true, want false")
	}
	if verified.InvalidReason != "insufficient_balance" {
		t.Fatalf("invalidReason = %q, want %q", verified.InvalidReason, "insufficient_balance")
	}
}
