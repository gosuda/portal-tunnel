package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	x402http "github.com/gosuda/x402-facilitator/resource/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
	"github.com/stretchr/testify/require"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// casperTestHash is a valid 64-hex CEP-18 contract hash for strict
// scheme/casper validation.
const casperTestHash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// Regression for the Casper shared /x402/prepare path: the challenge must
// publish the gate-canonical requirements (extra.paymentFlow pinned), so a
// client that echoes accepts[0] as its accepted contract passes the paid
// route's gate instead of failing the requirements match.
func TestCasperPrepareChallengePaysThroughGate(t *testing.T) {
	var mu sync.Mutex
	var authHeaders []string
	facilitator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/verify":
			_ = json.NewEncoder(w).Encode(facilitatortypes.PaymentVerifyResponse{
				IsValid: true,
				Payer:   "account-hash-" + casperTestHash,
			})
		case "/settle":
			_ = json.NewEncoder(w).Encode(facilitatortypes.PaymentSettleResponse{
				Success:     true,
				Transaction: "tx-casper-1",
				Network:     "casper:casper-test",
				Payer:       "account-hash-" + casperTestHash,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer facilitator.Close()

	var upstreamHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		_, _ = w.Write([]byte("casper-paid-body"))
	}))
	defer upstream.Close()

	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{
		Prefix:   "/paid",
		Upstream: upstream.URL,
		Amount:   "2.5",
	}}, types.X402Payment{
		Network:          "casper:casper-test",
		Asset:            casperTestHash,
		PayTo:            "account-hash-" + casperTestHash,
		Endpoints:        []string{facilitator.URL},
		FacilitatorToken: "test-token",
	})
	require.NoError(t, err)

	prepare := httptest.NewRequest(http.MethodPost, "/x402/prepare", strings.NewReader(`{"sender":"ignored","method":"GET","path":"/paid"}`))
	prepareRec := httptest.NewRecorder()
	handler.ServeHTTP(prepareRec, prepare)
	require.Equal(t, http.StatusPaymentRequired, prepareRec.Code, prepareRec.Body.String())

	var challenge struct {
		X402Version int                                    `json:"x402Version"`
		Accepts     []facilitatortypes.PaymentRequirements `json:"accepts"`
	}
	require.NoError(t, json.Unmarshal(prepareRec.Body.Bytes(), &challenge))
	require.Len(t, challenge.Accepts, 1)
	// The published contract must match the gate's canonical copy: a client
	// echoes it as accepted, and the gate requires its pinned paymentFlow.
	require.Equal(t, x402http.PaymentFlowUpfront, challenge.Accepts[0].Extra["paymentFlow"])
	require.Equal(t, "2500000000", challenge.Accepts[0].Amount)

	payload, err := json.Marshal(facilitatortypes.PaymentPayload{
		X402Version: int(facilitatortypes.X402VersionV2),
		Payload:     map[string]interface{}{"signature": "test-signature"},
		Accepted:    challenge.Accepts[0],
		Resource:    &facilitatortypes.ResourceInfo{URL: "https://paid.example.com/paid", MimeType: "text/html"},
	})
	require.NoError(t, err)

	paid := httptest.NewRequest(http.MethodGet, "/paid", nil)
	paid.Header.Set("PAYMENT-SIGNATURE", string(payload))
	paidRec := httptest.NewRecorder()
	handler.ServeHTTP(paidRec, paid)
	require.Equal(t, http.StatusOK, paidRec.Code, paidRec.Body.String())
	require.Contains(t, paidRec.Body.String(), "casper-paid-body")
	require.NotEmpty(t, paidRec.Header().Get(types.HeaderPaymentResponse))

	mu.Lock()
	defer mu.Unlock()
	// The upstream gate settles directly (no separate verify round trip),
	// so the hosted facilitator sees exactly one authorized call.
	require.Equal(t, []string{"test-token"}, authHeaders)
	require.Empty(t, upstreamHeaders.Get("Payment-Signature"))
	require.Empty(t, upstreamHeaders.Get("X-Payment"))
}
