package x402

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// stubFacilitator settles every payment with a canned response so the
// composition primitive can be exercised without a chain.
type stubFacilitator struct {
	settleCalls int
	response    *facilitatortypes.PaymentSettleResponse
}

func (f *stubFacilitator) Verify(context.Context, *facilitatortypes.PaymentPayload, *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentVerifyResponse, error) {
	return &facilitatortypes.PaymentVerifyResponse{IsValid: true}, nil
}

func (f *stubFacilitator) Settle(context.Context, *facilitatortypes.PaymentPayload, *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentSettleResponse, error) {
	f.settleCalls++
	return f.response, nil
}

func (f *stubFacilitator) Supported() *facilitatortypes.SupportedResponse {
	return &facilitatortypes.SupportedResponse{}
}

var (
	stubSettlement = facilitatortypes.PaymentSettleResponse{
		Success:     true,
		Payer:       "payer-01",
		Transaction: "tx-5f0e1d2c",
		Network:     facilitatortypes.Network(CasperTestnetNetwork),
	}
	stubRequirements = facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           CasperTestnetNetwork,
		Asset:             testWCSPRAsset,
		Amount:            "10000000",
		PayTo:             "account-hash-abc123",
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
	}
)

func newStubPayment(settlement facilitatortypes.PaymentSettleResponse) *Payment {
	payment := types.X402Payment{
		Network:      CasperTestnetNetwork,
		Asset:        testWCSPRAsset,
		PayTo:        "account-hash-abc123",
		Amount:       "10000000",
		ResourcePath: "/paid",
	}
	return &Payment{
		payment:      payment,
		facilitator:  &stubFacilitator{response: &settlement},
		requirements: stubRequirements,
	}
}

func paidPayloadHeader(t *testing.T, requirements facilitatortypes.PaymentRequirements) string {
	t.Helper()
	raw, err := json.Marshal(facilitatortypes.PaymentPayload{
		X402Version: int(facilitatortypes.X402VersionV2),
		Payload:     map[string]any{"signature": "deadbeef"},
		Accepted:    requirements,
	})
	if err != nil {
		t.Fatalf("marshal payment payload: %v", err)
	}
	return string(raw)
}

// Unpaid requests get the 402 challenge carrying the payment requirements, and
// the wrapped handler never runs.
func TestWrapChallengesUnpaidRequests(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("wrapped handler ran without a payment")
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	payment.Wrap(protected).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil))

	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	for _, name := range []string{types.HeaderPaymentRequired, types.HeaderXPaymentRequired} {
		if rec.Header().Get(name) == "" {
			t.Fatalf("missing %s challenge header", name)
		}
	}
	var body struct {
		Accepts []struct {
			Network string `json:"network"`
			Scheme  string `json:"scheme"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 402 body: %v", err)
	}
	if len(body.Accepts) != 1 || body.Accepts[0].Network != CasperTestnetNetwork || body.Accepts[0].Scheme != "exact" {
		t.Fatalf("accepts = %+v, want one %s exact requirement", body.Accepts, CasperTestnetNetwork)
	}
}

// A paid request settles exactly once, forwards with every payment header
// stripped and unrelated headers intact, and the trusted settlement receipt
// wins over anything the wrapped handler writes, including a forged challenge.
func TestWrapPaidRequestSettlesSanitizesAndKeepsTrustedHeaders(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	var sawHeader http.Header
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header
		w.Header().Set(types.HeaderPaymentResponse, "upstream")
		w.Header().Set(types.HeaderXPaymentResponse, "upstream")
		w.Header().Set(types.HeaderPaymentRequired, "upstream")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, paidPayloadHeader(t, stubRequirements))
	req.Header.Set(types.HeaderPaymentSignature, "sig")
	req.Header.Set(types.HeaderPaymentRequired, "challenge")
	req.Header.Set(types.HeaderXPaymentRequired, "challenge")
	req.Header.Set(types.HeaderPaymentResponse, "receipt")
	req.Header.Set(types.HeaderXPaymentResponse, "receipt")
	req.Header.Set("X-Keep-Me", "yes")
	rec := httptest.NewRecorder()
	payment.Wrap(protected).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if sawHeader == nil {
		t.Fatal("wrapped handler never ran")
	}
	for _, name := range []string{
		types.HeaderXPayment,
		types.HeaderPaymentSignature,
		types.HeaderPaymentRequired,
		types.HeaderXPaymentRequired,
		types.HeaderPaymentResponse,
		types.HeaderXPaymentResponse,
	} {
		if got := sawHeader.Get(name); got != "" {
			t.Fatalf("forwarded request kept payment header %s", name)
		}
	}
	if sawHeader.Get("X-Keep-Me") != "yes" {
		t.Fatal("forwarded request lost an unrelated header")
	}
	if got := rec.Header().Get(types.HeaderPaymentResponse); got == "" || got == "upstream" {
		t.Fatalf("payment response = %q, want trusted settlement", got)
	}
	if got := rec.Header().Get(types.HeaderXPaymentResponse); got != rec.Header().Get(types.HeaderPaymentResponse) {
		t.Fatalf("legacy response = %q, want same trusted settlement", got)
	}
	if got := rec.Header().Get(types.HeaderPaymentRequired); got != "" {
		t.Fatalf("upstream challenge leaked: %q", got)
	}
	stub, ok := payment.facilitator.(*stubFacilitator)
	if !ok || stub.settleCalls != 1 {
		t.Fatalf("settle calls = %+v, want exactly one", payment.facilitator)
	}
}

// Method filtering is a pass-through, not a rewrite: methods outside the paid
// list reach the handler with their headers intact, methods inside it still
// face the gate.
func TestWrapMethodFilterPassesUnpaidMethodsThrough(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	payment.methods = paymentMethodSet([]string{http.MethodPost})

	var ran bool
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if r.Method == http.MethodGet && r.Header.Get(types.HeaderXPayment) == "" {
			t.Error("unpaid GET had its payment headers stripped")
		}
	})

	// GET is outside the paid methods: it forwards untouched, headers intact.
	req := httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, "unsigned-garbage")
	rec := httptest.NewRecorder()
	payment.Wrap(protected).ServeHTTP(rec, req)
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("GET pass-through: ran=%v status=%d, want handler ran with 200", ran, rec.Code)
	}

	// POST is inside the paid methods: garbage payment gets the 402 challenge.
	ran = false
	req = httptest.NewRequest(http.MethodPost, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, "unsigned-garbage")
	rec = httptest.NewRecorder()
	payment.Wrap(protected).ServeHTTP(rec, req)
	if ran {
		t.Fatal("wrapped handler ran for a failed POST payment")
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("POST status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
}

// blockingFacilitator never settles on its own: Settle returns only when its
// context is done, mirroring a facilitator that stops answering.
type blockingFacilitator struct{ stubFacilitator }

func (f *blockingFacilitator) Settle(ctx context.Context, _ *facilitatortypes.PaymentPayload, _ *facilitatortypes.PaymentRequirements) (*facilitatortypes.PaymentSettleResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A paid request whose inbound context carries no deadline must not hang on a
// stuck facilitator: the configured RequestTimeout bounds settlement and the
// request fails with the 402 challenge instead.
func TestWrapBoundsSettlementByRequestTimeout(t *testing.T) {
	t.Parallel()
	payment := newStubPayment(stubSettlement)
	payment.payment.RequestTimeout = 20 * time.Millisecond
	payment.facilitator = &blockingFacilitator{}

	var ran bool
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, paidPayloadHeader(t, stubRequirements))
	served := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		payment.Wrap(protected).ServeHTTP(rec, req)
		served <- rec
	}()

	select {
	case rec := <-served:
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusPaymentRequired)
		}
		if ran {
			t.Fatal("wrapped handler ran after a failed settlement")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("settlement never returned: RequestTimeout did not bound the facilitator call")
	}
}

// An empty method list pays every method, so a blank configured method must be
// rejected as a configuration error instead of silently widening the gate.
func TestNewPaymentRejectsBlankMethod(t *testing.T) {
	_, err := NewPayment(types.X402Payment{
		Network:          CasperTestnetNetwork,
		Asset:            testWCSPRAsset,
		PayTo:            "Account-Hash-ABC123",
		Amount:           "0.25",
		FacilitatorToken: testFacilitatorToken,
		Methods:          []string{http.MethodPost, " "},
	})
	if err == nil {
		t.Fatal("NewPayment() error = nil, want blank payment method error")
	}
}

// The prepare endpoint is POST-only with JSON validation, and a valid prepare
// request reaches the prepare response path: the wallet-facing challenge
// document echoing the requested resource path. Requirement construction
// (motes amount, requirement network values) is owned by casper_test.go, so
// only presence of a usable requirements entry is asserted here.
func TestPrepareHandlerGatesAndRoutesToWritePrepare(t *testing.T) {
	payment, err := NewCasperPayment(types.X402Payment{
		Testnet:          true,
		Asset:            testWCSPRAsset,
		PayTo:            "account-hash-abc123",
		Amount:           "0.01",
		Endpoints:        []string{"https://facilitator.example"},
		FacilitatorToken: testFacilitatorToken,
	})
	if err != nil {
		t.Fatalf("NewCasperPayment: %v", err)
	}
	prepare := payment.PrepareHandler()

	rec := httptest.NewRecorder()
	prepare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example"+types.X402PreparePath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}

	rec = httptest.NewRecorder()
	prepare.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader("{not json")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	rec = httptest.NewRecorder()
	prepare.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader(`{"sender":"sender-01","path":"/custom/resource"}`)))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("prepare status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	var challenge struct {
		Resource *struct {
			URL string `json:"url"`
		} `json:"resource"`
		Accepts []struct {
			Network string `json:"network"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode prepare challenge: %v", err)
	}
	if challenge.Resource == nil || challenge.Resource.URL != "https://public.example/custom/resource" {
		t.Fatalf("resource = %+v, want the requested /custom/resource URL", challenge.Resource)
	}
	if len(challenge.Accepts) != 1 || challenge.Accepts[0].Network == "" {
		t.Fatalf("accepts = %+v, want one requirement carrying a network", challenge.Accepts)
	}
}

// USDCPaymentHandler layers its own method gate and settlement-result callback
// on the same settleAndDecorate machinery Wrap exercises above. Its distinct
// contract: a method outside the gate never reaches settlement, and a paid
// request hands the mapped settlement result to the callback.
func TestUSDCPaymentHandlerProtectsPathWithWrappedFlow(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	var results []types.X402PaymentResult
	handler := &USDCPaymentHandler{
		payment:       payment,
		protectedPath: "/paid",
		method:        http.MethodPost,
		handler: func(_ http.ResponseWriter, _ *http.Request, result types.X402PaymentResult) {
			results = append(results, result)
		},
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if stub, ok := payment.facilitator.(*stubFacilitator); !ok || stub.settleCalls != 0 {
		t.Fatal("settlement ran for a method outside the handler gate")
	}

	req := httptest.NewRequest(http.MethodPost, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, paidPayloadHeader(t, stubRequirements))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("paid POST status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(results) != 1 || results[0].TransactionID != "tx-5f0e1d2c" || results[0].Payer != "payer-01" || results[0].Network != CasperTestnetNetwork {
		t.Fatalf("results = %+v, want the stub settlement mapping", results)
	}
}

var _ facilitatorcore.Facilitator = (*stubFacilitator)(nil)
