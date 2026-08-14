package x402

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestCasperNetwork(t *testing.T) {
	if got := CasperNetwork(false); got != CasperMainnetNetwork {
		t.Fatalf("CasperNetwork(false) = %q, want %q", got, CasperMainnetNetwork)
	}
	if got := CasperNetwork(true); got != CasperTestnetNetwork {
		t.Fatalf("CasperNetwork(true) = %q, want %q", got, CasperTestnetNetwork)
	}
}

func TestIsCasperNetwork(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    bool
	}{
		{name: "mainnet", network: CasperMainnetNetwork, want: true},
		{name: "testnet", network: CasperTestnetNetwork, want: true},
		{name: "mixed case with spaces", network: "  Casper:Casper-Test ", want: true},
		{name: "sui", network: MainnetNetwork, want: false},
		{name: "empty", network: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCasperNetwork(tt.network); got != tt.want {
				t.Fatalf("IsCasperNetwork(%q) = %v, want %v", tt.network, got, tt.want)
			}
		})
	}
}

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

func TestFormatCSPRAtomicAmount(t *testing.T) {
	tests := []struct {
		name   string
		amount string
		want   string
	}{
		{name: "whole", amount: "1000000000", want: "1 wCSPR"},
		{name: "fraction", amount: "10000000", want: "0.01 wCSPR"},
		{name: "one mote", amount: "1", want: "0.000000001 wCSPR"},
		{name: "empty", amount: "", want: ""},
		{name: "invalid", amount: "abc", want: "abc motes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCSPRAtomicAmount(tt.amount); got != tt.want {
				t.Fatalf("FormatCSPRAtomicAmount(%q) = %q, want %q", tt.amount, got, tt.want)
			}
		})
	}
}

func TestNormalizeCasperAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{
			name:    "account hash lowercased",
			address: "  Account-Hash-1B2C3D  ",
			want:    "account-hash-1b2c3d",
		},
		{
			name:    "public key",
			address: "01A1B2C3",
			want:    "01a1b2c3",
		},
		{name: "empty", address: "   ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeCasperAddress(tt.address); got != tt.want {
				t.Fatalf("NormalizeCasperAddress(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}

const testWCSPRAsset = "hash-9c0d3fd7b1d9b5a94b13a5df0b1c8f1a0b3e5d7c9a1b3d5f7092a4c6e8b0d2f4"
const testFacilitatorToken = "test-token"

func TestNewCasperPayment(t *testing.T) {
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
	if payment.requirements.Network != CasperTestnetNetwork {
		t.Fatalf("network = %q, want %q", payment.requirements.Network, CasperTestnetNetwork)
	}
	if payment.requirements.Scheme != string(facilitatortypes.Exact) {
		t.Fatalf("scheme = %q, want %q", payment.requirements.Scheme, facilitatortypes.Exact)
	}
	if payment.requirements.Amount != "250000000" {
		t.Fatalf("amount = %q, want %q", payment.requirements.Amount, "250000000")
	}
	if payment.requirements.PayTo != "account-hash-abc123" {
		t.Fatalf("payTo = %q, want %q", payment.requirements.PayTo, "account-hash-abc123")
	}
	if payment.requirements.MaxTimeoutSeconds != defaultMaxTimeoutSeconds {
		t.Fatalf("maxTimeoutSeconds = %d, want %d", payment.requirements.MaxTimeoutSeconds, defaultMaxTimeoutSeconds)
	}
	if got := payment.requirements.Extra["asset"]; got != "wCSPR" {
		t.Fatalf("extra asset = %v, want wCSPR", got)
	}
	if got := payment.payment.NetworkName; got != "Casper Testnet" {
		t.Fatalf("network name = %q, want %q", got, "Casper Testnet")
	}
	if payment.facilitator == nil {
		t.Fatal("facilitator is nil")
	}
	if payment.payment.FacilitatorToken != "" {
		t.Fatal("facilitator token retained in normalized payment")
	}
}

func TestNewCasperPaymentErrors(t *testing.T) {
	tests := []struct {
		name    string
		payment types.X402Payment
	}{
		{
			name:    "unsupported network",
			payment: types.X402Payment{Network: "casper:nope", Asset: testWCSPRAsset, PayTo: "01ab", Amount: "1"},
		},
		{
			name:    "missing asset",
			payment: types.X402Payment{Network: CasperMainnetNetwork, PayTo: "01ab", Amount: "1"},
		},
		{
			name:    "missing pay to",
			payment: types.X402Payment{Network: CasperMainnetNetwork, Asset: testWCSPRAsset, Amount: "1"},
		},
		{
			name:    "invalid amount",
			payment: types.X402Payment{Network: CasperMainnetNetwork, Asset: testWCSPRAsset, PayTo: "01ab", Amount: "-1"},
		},
		{
			name:    "missing default facilitator token",
			payment: types.X402Payment{Network: CasperMainnetNetwork, Asset: testWCSPRAsset, PayTo: "01ab", Amount: "1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewCasperPayment(tt.payment); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCasperFacilitatorSupported(t *testing.T) {
	facilitator, err := newCasperFacilitator(CasperMainnetNetwork, testFacilitatorToken)
	if err != nil {
		t.Fatalf("newCasperFacilitator: %v", err)
	}
	supported := facilitator.Supported()
	if len(supported.Kinds) != 1 {
		t.Fatalf("kinds = %d, want 1", len(supported.Kinds))
	}
	kind := supported.Kinds[0]
	if kind.Network != CasperMainnetNetwork {
		t.Fatalf("kind network = %q, want %q", kind.Network, CasperMainnetNetwork)
	}
	if kind.Scheme != string(facilitatortypes.Exact) {
		t.Fatalf("kind scheme = %q, want %q", kind.Scheme, facilitatortypes.Exact)
	}
	if kind.X402Version != int(facilitatortypes.X402VersionV2) {
		t.Fatalf("kind x402Version = %d, want %d", kind.X402Version, facilitatortypes.X402VersionV2)
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
		Payload:     map[string]interface{}{"signature": "deadbeef"},
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

func TestCasperFacilitatorNilArgs(t *testing.T) {
	facilitator, err := newCasperFacilitator(CasperMainnetNetwork, testFacilitatorToken)
	if err != nil {
		t.Fatalf("newCasperFacilitator: %v", err)
	}
	if _, err := facilitator.Verify(context.Background(), nil, nil); err == nil {
		t.Fatal("Verify(nil, nil) expected an error")
	}
	if _, err := facilitator.Settle(context.Background(), nil, nil); err == nil {
		t.Fatal("Settle(nil, nil) expected an error")
	}
}
