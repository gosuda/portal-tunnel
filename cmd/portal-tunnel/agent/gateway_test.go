package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	rpcv2 "github.com/gosuda/x402-facilitator/scheme/sui/grpc/pb/sui/rpc/v2"
	"google.golang.org/grpc"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func testHashHex() string { return strings.Repeat("ab", 32) }

func testSuiContract() types.X402Payment {
	return types.X402Payment{
		Testnet: true,
		PayTo:   "0x" + strings.Repeat("a", 64),
	}
}

func testCasperContract() types.X402Payment {
	return types.X402Payment{
		Network:          "casper:casper-test",
		Asset:            "hash-" + testHashHex(),
		PayTo:            "account-hash-" + strings.Repeat("cd", 32),
		FacilitatorToken: "secret-casper-token",
	}
}

// newTestUpstream returns an upstream that answers every request with "api"
// and reports the forwarded headers it saw.
func newTestUpstream(t *testing.T, forwarded chan<- http.Header) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forwarded != nil {
			forwarded <- r.Header.Clone()
		}
		_, _ = w.Write([]byte("api"))
	}))
}

func postPrepare(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, types.X402PreparePath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// Unpaid requests to a paid route get the x402 challenge and the wrapped
// route never runs; unpaid routes stay untouched and a fully unpaid gateway
// answers nothing on the reserved x402 paths.
func TestComposeHTTPRoutesChallengesUnpaidRequests(t *testing.T) {
	t.Parallel()

	upstream := newTestUpstream(t, nil)
	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/", Upstream: upstream.URL, Amount: "0.01"},
		{Prefix: "/api", Upstream: upstream.URL},
	}, testSuiContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	for _, name := range []string{types.HeaderPaymentRequired, types.HeaderXPaymentRequired} {
		if rec.Header().Get(name) == "" {
			t.Fatalf("missing %s challenge header", name)
		}
	}
	var challenge struct {
		X402Version int `json:"x402Version"`
		Resource    struct {
			URL string `json:"url"`
		} `json:"resource"`
		Accepts []struct {
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
			Amount  string `json:"amount"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode 402 body: %v", err)
	}
	if challenge.X402Version != 2 {
		t.Fatalf("x402Version = %d, want 2", challenge.X402Version)
	}
	// The gate challenge carries the route prefix as its resource URL; the
	// per-request absolute URL moved to the prepare response.
	if challenge.Resource.URL != "/" {
		t.Fatalf("resource url = %q, want the route prefix", challenge.Resource.URL)
	}
	if len(challenge.Accepts) != 1 || challenge.Accepts[0].Scheme != "exact" || challenge.Accepts[0].Network != "sui:testnet" {
		t.Fatalf("accepts = %+v, want one sui:testnet exact requirement", challenge.Accepts)
	}
	if challenge.Accepts[0].Amount != "10000" {
		t.Fatalf("amount = %q, want 0.01 USDC in atomic units", challenge.Accepts[0].Amount)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/api/users", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "api" {
		t.Fatalf("unpaid route status = %d body = %q, want passthrough", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(types.HeaderPaymentRequired) != "" {
		t.Fatal("unpaid route answered with a payment challenge header")
	}

	// The paid gateway owns the reserved paths: client.js is the shared
	// wallet client, not a proxied path.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, types.X402ClientPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("client.js status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("client.js content type = %q, want javascript", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("client.js body is empty")
	}
}

// Method filtering is a pass-through, not a rewrite: methods outside the
// paid list reach the upstream with their headers intact, methods inside it
// still face the gate.
func TestComposeHTTPRoutesMethodFilterPassesThrough(t *testing.T) {
	t.Parallel()

	forwarded := make(chan http.Header, 1)
	upstream := newTestUpstream(t, forwarded)
	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Methods: []string{"get"}, Amount: "0.01"},
	}, testSuiContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://public.example/paid/x", nil)
	req.Header.Set(types.HeaderXPayment, "unsigned-garbage")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "api" {
		t.Fatalf("POST status = %d body = %q, want passthrough outside paid methods", rec.Code, rec.Body.String())
	}
	header := <-forwarded
	if header.Get(types.HeaderXPayment) != "unsigned-garbage" {
		t.Fatal("unpaid method had its payment header stripped")
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid/x", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("GET status = %d, want payment challenge", rec.Code)
	}
}

// suiLedgerFake is a minimal Sui RPC fake covering exactly the calls the
// shared prepare makes for a balance-covered sender: the epoch lookup and
// the balance check. The coin-object listing stays unimplemented on purpose:
// a balance-covered sender must not reach it, so a spurious call fails the
// prepare loudly.
type suiLedgerFake struct {
	rpcv2.UnimplementedLedgerServiceServer
	rpcv2.UnimplementedStateServiceServer
	rpcv2.UnimplementedTransactionExecutionServiceServer
}

func (s *suiLedgerFake) GetServiceInfo(context.Context, *rpcv2.GetServiceInfoRequest) (*rpcv2.GetServiceInfoResponse, error) {
	return &rpcv2.GetServiceInfoResponse{Epoch: ptr(uint64(42))}, nil
}

func (s *suiLedgerFake) GetBalance(context.Context, *rpcv2.GetBalanceRequest) (*rpcv2.GetBalanceResponse, error) {
	return &rpcv2.GetBalanceResponse{Balance: &rpcv2.Balance{
		CoinType:       ptr(suischeme.TestnetUSDCType),
		Balance:        ptr(uint64(20000)),
		AddressBalance: ptr(uint64(20000)),
		CoinBalance:    ptr(uint64(0)),
	}}, nil
}

func ptr[T any](value T) *T { return &value }

func newSuiLedgerEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	rpcv2.RegisterLedgerServiceServer(server, &suiLedgerFake{})
	rpcv2.RegisterStateServiceServer(server, &suiLedgerFake{})
	rpcv2.RegisterTransactionExecutionServiceServer(server, &suiLedgerFake{})
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	go func() {
		_ = server.Serve(listener)
	}()
	return "http://" + listener.Addr().String()
}

// The shared prepare endpoint selects the matched route's contract: Sui
// routes delegate to the upstream prepare operation, Casper routes answer
// with the challenge because their wallets sign the published requirements
// directly.
func TestComposeHTTPRoutesPrepareServesRouteContract(t *testing.T) {
	t.Parallel()

	t.Run("sui route prepares the payment", func(t *testing.T) {
		t.Parallel()
		upstream := newTestUpstream(t, nil)
		handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
			{Prefix: "/", Upstream: upstream.URL, Amount: "0.01"},
		}, func() types.X402Payment {
			contract := testSuiContract()
			contract.Endpoints = []string{newSuiLedgerEndpoint(t)}
			return contract
		}())
		if err != nil {
			t.Fatalf("ComposeHTTPRoutes() error = %v", err)
		}

		rec := postPrepare(t, handler, `{"sender":"0x1234","path":"/"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("prepare status = %d body = %q, want 200", rec.Code, rec.Body.String())
		}
		var body struct {
			X402Version         int `json:"x402Version"`
			PaymentRequirements struct {
				Scheme            string         `json:"scheme"`
				Network           string         `json:"network"`
				Asset             string         `json:"asset"`
				Amount            string         `json:"amount"`
				PayTo             string         `json:"payTo"`
				MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
				Extra             map[string]any `json:"extra"`
			} `json:"paymentRequirements"`
			Resource struct {
				URL      string `json:"url"`
				MimeType string `json:"mimeType"`
			} `json:"resource"`
			PrepareTransaction *struct {
				Transaction string `json:"transaction"`
			} `json:"prepareTransaction"`
			PaymentTransaction struct {
				Transaction string `json:"transaction"`
			} `json:"paymentTransaction"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode prepare body: %v", err)
		}
		if body.X402Version != 2 {
			t.Fatalf("x402Version = %d, want 2", body.X402Version)
		}
		requirements := body.PaymentRequirements
		if requirements.Scheme != "exact" || requirements.Network != "sui:testnet" || requirements.Amount != "10000" {
			t.Fatalf("requirements = %+v, want the route's sui:testnet contract", requirements)
		}
		if requirements.Asset != suischeme.TestnetUSDCType {
			t.Fatalf("asset = %q, want the network's USDC coin type", requirements.Asset)
		}
		if requirements.PayTo != testSuiContract().PayTo {
			t.Fatalf("payTo = %q, want the contract pay-to", requirements.PayTo)
		}
		if requirements.MaxTimeoutSeconds != 60 {
			t.Fatalf("maxTimeoutSeconds = %d, want the default 60", requirements.MaxTimeoutSeconds)
		}
		// Clients echo the prepare requirements as their accepted contract,
		// so the gate's pinned paymentFlow must survive the echo.
		if requirements.Extra["paymentFlow"] != "upfront" || requirements.Extra["asset"] != "USDC" {
			t.Fatalf("extra = %+v, want the upfront USDC transfer method", requirements.Extra)
		}
		if body.Resource.URL != "http://example.com/" || body.Resource.MimeType != "text/html" {
			t.Fatalf("resource = %+v, want the per-request absolute URL", body.Resource)
		}
		// The fake sender's address balance covers the amount: no
		// consolidation transaction, only the payment transaction.
		if body.PrepareTransaction != nil {
			t.Fatalf("prepareTransaction = %+v, want none for a covered sender", body.PrepareTransaction)
		}
		paymentTx, err := base64.StdEncoding.DecodeString(body.PaymentTransaction.Transaction)
		if err != nil || len(paymentTx) == 0 {
			t.Fatalf("paymentTransaction = %q, want non-empty base64 (err = %v)", body.PaymentTransaction.Transaction, err)
		}
	})

	t.Run("casper route answers with the challenge", func(t *testing.T) {
		t.Parallel()
		upstream := newTestUpstream(t, nil)
		handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
			{Prefix: "/casper", Upstream: upstream.URL, Amount: "0.25"},
		}, testCasperContract())
		if err != nil {
			t.Fatalf("ComposeHTTPRoutes() error = %v", err)
		}

		rec := postPrepare(t, handler, `{"path":"/casper"}`)
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("prepare status = %d body = %q, want the 402 challenge", rec.Code, rec.Body.String())
		}
		var challenge struct {
			X402Version int    `json:"x402Version"`
			Error       string `json:"error"`
			Resource    struct {
				URL string `json:"url"`
			} `json:"resource"`
			Accepts []struct {
				Network string `json:"network"`
				Amount  string `json:"amount"`
			} `json:"accepts"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
			t.Fatalf("decode challenge body: %v", err)
		}
		if challenge.X402Version != 2 || challenge.Error != "payment required" {
			t.Fatalf("challenge = %+v, want the v2 payment-required challenge", challenge)
		}
		if challenge.Resource.URL != "http://example.com/casper" {
			t.Fatalf("resource url = %q, want the per-request absolute URL", challenge.Resource.URL)
		}
		if len(challenge.Accepts) != 1 || challenge.Accepts[0].Network != "casper:casper-test" || challenge.Accepts[0].Amount != "250000000" {
			t.Fatalf("accepts = %+v, want 0.25 wCSPR in motes on casper:casper-test", challenge.Accepts)
		}
		// Portal's challenge wire shape: the raw body is echoed base64
		// encoded in both challenge headers.
		encoded := base64.StdEncoding.EncodeToString(rec.Body.Bytes())
		for _, name := range []string{types.HeaderPaymentRequired, types.HeaderXPaymentRequired} {
			if rec.Header().Get(name) != encoded {
				t.Fatalf("header %s = %q, want the challenge body base64", name, encoded)
			}
		}
		// The facilitator token is a server-side credential: the challenge
		// must never disclose it, in the body or in any header.
		exposed := rec.Body.String()
		for name, values := range rec.Header() {
			exposed += name + ": " + strings.Join(values, ",") + "\n"
		}
		if strings.Contains(exposed, "secret-casper-token") {
			t.Fatal("challenge disclosed the facilitator token")
		}
	})
}

// The prepare endpoint routes only within the paid surface: unpaid routes,
// unrouted paths, oversized bodies, malformed JSON, and wrong methods all
// fail before any payment layer runs.
func TestComposeHTTPRoutesPrepareRejects(t *testing.T) {
	t.Parallel()

	upstream := newTestUpstream(t, nil)
	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Amount: "0.01"},
		{Prefix: "/api", Upstream: upstream.URL},
	}, testSuiContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	t.Run("unpaid route", func(t *testing.T) {
		t.Parallel()
		rec := postPrepare(t, handler, `{"path":"/api"}`)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "x402 payment is not enabled for path") {
			t.Fatalf("status = %d body = %q, want not-enabled 404", rec.Code, rec.Body.String())
		}
	})
	t.Run("unrouted path", func(t *testing.T) {
		t.Parallel()
		rec := postPrepare(t, handler, `{"path":"/nowhere"}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
	t.Run("blank path", func(t *testing.T) {
		t.Parallel()
		rec := postPrepare(t, handler, `{"path":" "}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "path is required") {
			t.Fatalf("status = %d body = %q, want blank path 400", rec.Code, rec.Body.String())
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		body := `{"sender":"` + strings.Repeat("a", int(types.X402RequestBodyLimit)) + `"}`
		rec := postPrepare(t, handler, body)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
		}
		// Portal's shared endpoints keep the JSON API envelope on errors.
		var envelope struct {
			OK    bool `json:"ok"`
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if envelope.OK || envelope.Error == nil || envelope.Error.Code != "invalid_request" {
			t.Fatalf("envelope = %+v, want the invalid_request API error", envelope)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		t.Parallel()
		rec := postPrepare(t, handler, `{"sender":`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		var envelope struct {
			Error *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if envelope.Error == nil || envelope.Error.Code != "invalid_json" || envelope.Error.Message != "invalid payment prepare request" {
			t.Fatalf("envelope = %+v, want the invalid_json API error", envelope)
		}
	})
	t.Run("method is post only", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, types.X402PreparePath, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})
}

// ComposeHTTPRoutes validates the payment contract up front: every invalid
// composition dies with a configuration error instead of mounting a broken
// gate. The Casper pay-to fixture pins the strict upstream normalization:
// the lenient portal form "account-hash-abc123" is no longer accepted, only
// account-hash-<64 hex>.
func TestComposeHTTPRoutesRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	deadUpstream := "http://127.0.0.1:9"
	validCasper := testCasperContract()
	tests := []struct {
		name     string
		routes   []ExposedHTTPRoute
		contract types.X402Payment
		wantErr  string
	}{
		{
			name:     "blank payment method",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.01", Methods: []string{http.MethodPost, " "}}},
			contract: testSuiContract(),
			wantErr:  "x402 payment method is required",
		},
		{
			name:     "payment methods require an amount",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Methods: []string{"GET"}}},
			contract: testSuiContract(),
			wantErr:  "payment methods require amount",
		},
		{
			name:     "amount requires pay-to",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.01"}},
			contract: types.X402Payment{Testnet: true},
			wantErr:  "amount requires x402 pay-to",
		},
		{
			name:     "unsupported network",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.01"}},
			contract: types.X402Payment{Network: "eip155:84532", PayTo: "0xabc"},
			wantErr:  `unsupported x402 network "eip155:84532"`,
		},
		{
			name:   "casper strict pay-to",
			routes: []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.25"}},
			contract: func() types.X402Payment {
				contract := validCasper
				contract.PayTo = "account-hash-abc123"
				return contract
			}(),
			wantErr: "requires a Casper pay-to address",
		},
		{
			name:     "casper asset required",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.25"}},
			contract: func() types.X402Payment { contract := validCasper; contract.Asset = ""; return contract }(),
			wantErr:  "wCSPR CEP-18 contract hash",
		},
		{
			name:     "casper hosted facilitator requires token",
			routes:   []ExposedHTTPRoute{{Prefix: "/paid", Upstream: deadUpstream, Amount: "0.25"}},
			contract: func() types.X402Payment { contract := validCasper; contract.FacilitatorToken = ""; return contract }(),
			wantErr:  "CSPR.cloud x402 facilitator requires an authorization token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ComposeHTTPRoutes(tt.routes, tt.contract)
			if err == nil {
				t.Fatalf("ComposeHTTPRoutes() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ComposeHTTPRoutes() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// Strict Casper fixtures compose: account-hash-<64 hex> pay-to and a valid
// CEP-18 contract hash are accepted.
func TestComposeHTTPRoutesAcceptsStrictCasperFixtures(t *testing.T) {
	t.Parallel()

	upstream := newTestUpstream(t, nil)
	_, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Amount: "0.25"},
	}, testCasperContract())
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
}

// Gateway-level wrapped-flow smoke: a paid request settles against the
// route's facilitator exactly once, reaches the routed upstream with every
// payment header stripped, and the settlement receipt wins over anything the
// upstream writes.
func TestComposeHTTPRoutesPaidRequestSettlesAndStripsHeaders(t *testing.T) {
	t.Parallel()

	var settleMu sync.Mutex
	settleCalls := 0
	settle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/settle" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "secret-casper-token" {
			http.Error(w, "missing facilitator auth", http.StatusUnauthorized)
			return
		}
		settleMu.Lock()
		settleCalls++
		settleMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"transaction":"tx-smoke-01","payer":"payer-01","network":"casper:casper-test"}`))
	}))
	t.Cleanup(settle.Close)

	forwarded := make(chan http.Header, 1)
	upstream := newTestUpstream(t, forwarded)
	contract := testCasperContract()
	contract.Endpoints = []string{settle.URL}
	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Amount: "0.25"},
	}, contract)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	// Echo the advertised contract: an unpaid request collects the 402
	// challenge, and its accepts[0] becomes the paid payload's accepted
	// requirements, exactly what a wallet client does.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
	var challenge struct {
		Accepts []json.RawMessage `json:"accepts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil || len(challenge.Accepts) != 1 {
		t.Fatalf("decode challenge accepts: %v (%+v)", err, challenge)
	}
	payload, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"payload":     map[string]any{"signature": "deadbeef"},
		"accepted":    json.RawMessage(challenge.Accepts[0]),
	})
	if err != nil {
		t.Fatalf("marshal payment payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example/paid", nil)
	req.Header.Set(types.HeaderPaymentSignature, string(payload))
	req.Header.Set("X-Keep-Me", "yes")
	req.Header.Set(types.HeaderPaymentResponse, "forged")
	req.Header.Set(types.HeaderPaymentRequired, "forged")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "api" {
		t.Fatalf("paid status = %d body = %q, want the routed upstream response", rec.Code, rec.Body.String())
	}

	header := <-forwarded
	for _, name := range []string{
		types.HeaderXPayment,
		types.HeaderPaymentSignature,
		types.HeaderPaymentRequired,
		types.HeaderXPaymentRequired,
		types.HeaderPaymentResponse,
		types.HeaderXPaymentResponse,
	} {
		if header.Get(name) != "" {
			t.Fatalf("forwarded request kept payment header %s", name)
		}
	}
	if header.Get("X-Keep-Me") != "yes" {
		t.Fatal("forwarded request lost an unrelated header")
	}
	if got := rec.Header().Get(types.HeaderPaymentResponse); got == "" || got == "forged" {
		t.Fatalf("payment response = %q, want the trusted settlement receipt", got)
	}
	settleMu.Lock()
	defer settleMu.Unlock()
	if settleCalls != 1 {
		t.Fatalf("settle calls = %d, want exactly one", settleCalls)
	}
}
