package gateway

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	x402http "github.com/gosuda/x402-facilitator/resource/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"
)

const (
	nanoTestPayTo     = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
	nanoTestOtherPeer = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
	// 0.01 XNO in raw (1 XNO = 10^30 raw).
	nanoTestRaw = "10000000000000000000000000000"
)

// newNanoRPCNode stands in for a Nano RPC node answering block_info from a
// fixed ledger of block hash -> block_info response.
func newNanoRPCNode(t *testing.T, ledger map[string]map[string]any) *httptest.Server {
	t.Helper()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"`
			Hash   string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Action != "block_info" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		block, ok := ledger[req.Hash]
		if !ok {
			block = map[string]any{"error": "Block not found"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(block)
	}))
	t.Cleanup(node.Close)
	return node
}

func nanoSendBlock(destination, amount, confirmed string) map[string]any {
	return map[string]any{
		"block_account": nanoTestOtherPeer,
		"amount":        amount,
		"confirmed":     confirmed,
		"subtype":       "send",
		"contents": map[string]any{
			"type":            "state",
			"link_as_account": destination,
		},
	}
}

func TestComposeHTTPRoutesNanoPayment(t *testing.T) {
	t.Parallel()
	const (
		paidHash        = "ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113"
		underpaidHash   = "1111111111111111111111111111111111111111111111111111111111111111"
		wrongPayeeHash  = "2222222222222222222222222222222222222222222222222222222222222222"
		unconfirmedHash = "3333333333333333333333333333333333333333333333333333333333333333"
	)
	ledger := map[string]map[string]any{
		paidHash:        nanoSendBlock(nanoTestPayTo, nanoTestRaw, "true"),
		underpaidHash:   nanoSendBlock(nanoTestPayTo, "9999999999999999999999999999", "true"),
		wrongPayeeHash:  nanoSendBlock(nanoTestOtherPeer, nanoTestRaw, "true"),
		unconfirmedHash: nanoSendBlock(nanoTestPayTo, nanoTestRaw, "false"),
	}
	nodeA := newNanoRPCNode(t, ledger)
	nodeB := newNanoRPCNode(t, ledger)

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "paid content")
	}))
	t.Cleanup(upstream.Close)

	handler, err := ComposeHTTPRoutes([]ExposedHTTPRoute{
		{Prefix: "/paid", Upstream: upstream.URL, Amount: "0.01"},
		{Prefix: "/also-paid", Upstream: upstream.URL, Amount: "0.01"},
	}, X402Payment{X402Config: X402Config{
		Network:   "nano:mainnet",
		PayTo:     strings.ToUpper(nanoTestPayTo[:1]) + nanoTestPayTo[1:],
		Endpoints: []string{nodeA.URL, nodeB.URL},
	}})
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/paid/item", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid status = %d, want 402", rec.Code)
	}
	rawChallenge, err := base64.StdEncoding.DecodeString(rec.Header().Get(x402http.HeaderPaymentRequired))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	var challenge struct {
		Accepts []facilitatortypes.PaymentRequirements `json:"accepts"`
	}
	if err := json.Unmarshal(rawChallenge, &challenge); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if len(challenge.Accepts) != 1 {
		t.Fatalf("accepts = %d, want 1", len(challenge.Accepts))
	}
	accepted := challenge.Accepts[0]
	if accepted.Scheme != "exact" || accepted.Network != "nano:mainnet" || accepted.Asset != "XNO" ||
		accepted.Amount != nanoTestRaw || accepted.PayTo != nanoTestPayTo {
		t.Fatalf("accepted = %+v, want exact nano:mainnet XNO %s to %s", accepted, nanoTestRaw, nanoTestPayTo)
	}

	pay := func(path, blockHash string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(facilitatortypes.PaymentPayload{
			X402Version: int(facilitatortypes.X402VersionV2),
			Accepted:    accepted,
			Payload:     map[string]any{"blockHash": blockHash},
		})
		if err != nil {
			t.Fatalf("marshal payment: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
		req.Header.Set(x402http.HeaderPaymentSignature, base64.StdEncoding.EncodeToString(raw))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	for name, hash := range map[string]string{
		"underpaid":   underpaidHash,
		"wrong payee": wrongPayeeHash,
		"unconfirmed": unconfirmedHash,
		"unknown":     strings.Repeat("4", 64),
	} {
		if rec := pay("/paid/item", hash); rec.Code != http.StatusPaymentRequired {
			t.Fatalf("%s payment status = %d, want 402", name, rec.Code)
		}
	}
	if hits := upstreamHits.Load(); hits != 0 {
		t.Fatalf("upstream reached %d times before a valid payment", hits)
	}

	rec = pay("/paid/item", strings.ToLower(paidHash))
	if rec.Code != http.StatusOK || rec.Body.String() != "paid content" {
		t.Fatalf("paid status = %d body = %q, want 200 paid content", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(x402http.HeaderPaymentResponse) == "" {
		t.Fatal("paid response is missing the settlement receipt")
	}
	if hits := upstreamHits.Load(); hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits)
	}

	// A block hash pays once per gateway, including on another route with
	// the same price.
	for _, path := range []string{"/paid/item", "/also-paid/item"} {
		if rec := pay(path, paidHash); rec.Code != http.StatusPaymentRequired {
			t.Fatalf("replayed payment on %s status = %d, want 402", path, rec.Code)
		}
	}
	if hits := upstreamHits.Load(); hits != 1 {
		t.Fatalf("replayed payment reached upstream: hits = %d", hits)
	}
}

func TestComposeHTTPRoutesRejectsInvalidNanoContract(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		amount    string
		payTo     string
		endpoints []string
	}{
		"bad checksum":       {amount: "0.01", payTo: nanoTestPayTo[:len(nanoTestPayTo)-1] + "1"},
		"not a nano address": {amount: "0.01", payTo: "0x1234"},
		"sub-raw amount":     {amount: "0." + strings.Repeat("0", 30) + "1", payTo: nanoTestPayTo},
		"zero amount":        {amount: "0", payTo: nanoTestPayTo},
		"malformed amount":   {amount: "1e-3", payTo: nanoTestPayTo},
		"one rpc endpoint":   {amount: "0.01", payTo: nanoTestPayTo, endpoints: []string{"http://127.0.0.1:1", " http://127.0.0.1:1 "}},
	}
	for name, tt := range tests {
		_, err := ComposeHTTPRoutes([]ExposedHTTPRoute{{
			Prefix:   "/paid",
			Upstream: "http://127.0.0.1:1",
			Amount:   tt.amount,
		}}, X402Payment{X402Config: X402Config{
			Network:   "nano:mainnet",
			PayTo:     tt.payTo,
			Endpoints: tt.endpoints,
		}})
		if err == nil {
			t.Errorf("%s: ComposeHTTPRoutes() error = nil, want rejection", name)
		}
	}
}
