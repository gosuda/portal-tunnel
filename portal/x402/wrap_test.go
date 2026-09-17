package x402

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		Error   string `json:"error"`
		Accepts []struct {
			Network string `json:"network"`
			Scheme  string `json:"scheme"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 402 body: %v", err)
	}
	if body.Error != "payment required" {
		t.Fatalf("error = %q, want payment required", body.Error)
	}
	if len(body.Accepts) != 1 || body.Accepts[0].Network != CasperTestnetNetwork || body.Accepts[0].Scheme != "exact" {
		t.Fatalf("accepts = %+v, want one %s exact requirement", body.Accepts, CasperTestnetNetwork)
	}
}

func TestWrapSettlesAndForwardsSanitizedRequest(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	var sawHeader http.Header
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header
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
	for _, name := range []string{types.HeaderPaymentResponse, types.HeaderXPaymentResponse} {
		if rec.Header().Get(name) == "" {
			t.Fatalf("missing %s settlement header", name)
		}
	}
	stub, ok := payment.facilitator.(*stubFacilitator)
	if !ok || stub.settleCalls != 1 {
		t.Fatalf("settle calls = %+v, want exactly one", payment.facilitator)
	}
}

func TestWrapMethodFilterPassesUnpaidMethodsThrough(t *testing.T) {
	payment := newStubPayment(stubSettlement)
	payment.methods = paymentMethodSet([]string{"post"})

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

	// A paid POST settles and forwards.
	ran = false
	req = httptest.NewRequest(http.MethodPost, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, paidPayloadHeader(t, stubRequirements))
	rec = httptest.NewRecorder()
	payment.Wrap(protected).ServeHTTP(rec, req)
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("paid POST: ran=%v status=%d, want handler ran with 200", ran, rec.Code)
	}
}

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

	// Casper payments publish requirements instead of a server-built
	// transaction, so the prepare endpoint answers with the 402 requirements
	// document carrying the client-requested resource path.
	body := `{"sender":"sender-01","path":"/custom/resource"}`
	rec = httptest.NewRecorder()
	prepare.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402PreparePath, strings.NewReader(body)))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("casper prepare status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	var challenge struct {
		Resource *struct {
			URL string `json:"url"`
		} `json:"resource"`
		Accepts []struct {
			Amount  string `json:"amount"`
			Network string `json:"network"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode prepare challenge: %v", err)
	}
	if challenge.Resource == nil || challenge.Resource.URL != "https://public.example/custom/resource" {
		t.Fatalf("resource = %+v, want the requested /custom/resource URL", challenge.Resource)
	}
	if len(challenge.Accepts) != 1 || challenge.Accepts[0].Amount != "10000000" || challenge.Accepts[0].Network != CasperTestnetNetwork {
		t.Fatalf("accepts = %+v, want the casper requirement", challenge.Accepts)
	}
}

func TestClientJSServesSharedWalletClient(t *testing.T) {
	handler := newStubPayment(stubSettlement).ClientJSHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example"+types.X402ClientPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/javascript") {
		t.Fatalf("content type = %q, want application/javascript", got)
	}
	if rec.Body.Len() != len(clientJS) {
		t.Fatalf("body length = %d, want %d", rec.Body.Len(), len(clientJS))
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example"+types.X402ClientPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

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

	// Method outside the handler's gate is rejected before any settlement.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if stub, ok := payment.facilitator.(*stubFacilitator); !ok || stub.settleCalls != 0 {
		t.Fatal("settlement ran for a method outside the handler gate")
	}

	// Unpaid POST gets the challenge; the handler callback never runs.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://public.example/paid", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid POST status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	if len(results) != 0 {
		t.Fatal("handler callback ran without a settlement")
	}

	// Paid POST settles and hands the settlement result to the callback.
	req := httptest.NewRequest(http.MethodPost, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderXPayment, paidPayloadHeader(t, stubRequirements))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("paid POST status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(results) != 1 {
		t.Fatalf("results = %+v, want exactly one", results)
	}
	if results[0].TransactionID != "tx-5f0e1d2c" || results[0].Payer != "payer-01" || results[0].Network != CasperTestnetNetwork {
		t.Fatalf("result = %+v, want the stub settlement mapping", results[0])
	}
	if rec.Header().Get(types.HeaderPaymentResponse) == "" {
		t.Fatal("missing PAYMENT-RESPONSE settlement header")
	}
}

// The prepare response is the wallet-facing wire contract shared with
// client.js: the Portal DTO swap from facilitator types must not move a byte.
func TestX402PreparePaymentResponseWireShape(t *testing.T) {
	response := types.X402PreparePaymentResponse{
		X402Version: 2,
		PaymentRequirements: types.X402PaymentRequirements{
			Scheme:            "exact",
			Network:           CasperTestnetNetwork,
			Asset:             testWCSPRAsset,
			Amount:            "10000000",
			PayTo:             "account-hash-abc123",
			MaxTimeoutSeconds: 60,
			Extra:             map[string]any{"asset": "wCSPR"},
		},
		Resource: &types.X402ResourceInfo{
			URL:         "http://public.example/paid",
			Description: "protected resource",
			MimeType:    "text/html",
		},
		PrepareTransaction: &struct {
			Transaction string `json:"transaction"`
		}{Transaction: "cHJlcGFyZQ=="},
		PaymentTransaction: struct {
			Transaction string `json:"transaction"`
		}{Transaction: "cGF5"},
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal prepare response: %v", err)
	}
	want := `{"x402Version":2,` +
		`"paymentRequirements":{"scheme":"exact","network":"casper:casper-test","asset":"` + testWCSPRAsset + `","amount":"10000000","payTo":"account-hash-abc123","maxTimeoutSeconds":60,"extra":{"asset":"wCSPR"}},` +
		`"resource":{"url":"http://public.example/paid","description":"protected resource","mimeType":"text/html"},` +
		`"prepareTransaction":{"transaction":"cHJlcGFyZQ=="},` +
		`"paymentTransaction":{"transaction":"cGF5"}}`
	if string(raw) != want {
		t.Fatalf("prepare response wire shape drifted:\n got %s\nwant %s", raw, want)
	}
}

var _ facilitatorcore.Facilitator = (*stubFacilitator)(nil)
