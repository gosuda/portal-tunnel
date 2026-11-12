package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
)

const nanoClaimsTestPaidHash = "ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113"

func composeNanoClaimsHandler(t *testing.T, contract X402Config, hits *atomic.Int32) (http.Handler, error) {
	t.Helper()
	ledger := map[string]map[string]any{
		nanoClaimsTestPaidHash: nanoSendBlock(nanoTestPayTo, nanoTestRawFor001XNO, "true"),
	}
	nodeA := newNanoRPCNode(t, ledger)
	nodeB := newNanoRPCNode(t, ledger)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "paid content")
	}))
	t.Cleanup(upstream.Close)
	contract.Network = "nano:mainnet"
	contract.PayTo = nanoTestPayTo
	contract.Endpoints = []string{nodeA.URL, nodeB.URL}
	return ComposeHTTPRoutes([]ExposedHTTPRoute{{Prefix: "/paid", Upstream: upstream.URL, Amount: "0.01"}}, contract)
}

func nanoClaimsChallenge(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/paid/item", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid status = %d, want 402", rec.Code)
	}
	return rec
}

func TestComposeHTTPRoutesNanoClaimsSurviveRestart(t *testing.T) {
	t.Parallel()
	claims := filepath.Join(t.TempDir(), "nano-claims.jsonl")
	var hits atomic.Int32

	first, err := composeNanoClaimsHandler(t, X402Config{NanoClaimsFile: claims}, &hits)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	accepted := decodeNanoPaymentFixtureChallenge(t, nanoClaimsChallenge(t, first))
	if rec := payNanoPath(t, first, accepted, "/paid/item", nanoClaimsTestPaidHash); rec.Code != http.StatusOK {
		t.Fatalf("first payment status = %d, want 200", rec.Code)
	}
	info, err := os.Stat(claims)
	if err != nil {
		t.Fatalf("claim log not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("claim log mode = %o, want 600", perm)
	}

	// A new gateway on the same claim log is what a restart builds.
	restarted, err := composeNanoClaimsHandler(t, X402Config{NanoClaimsFile: claims}, &hits)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() after restart error = %v", err)
	}
	accepted = decodeNanoPaymentFixtureChallenge(t, nanoClaimsChallenge(t, restarted))
	if rec := payNanoPath(t, restarted, accepted, "/paid/item", nanoClaimsTestPaidHash); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("payment replayed after restart: status = %d, want 402", rec.Code)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}

func TestComposeHTTPRoutesNanoClaimsFileUnreadableRefusesToStart(t *testing.T) {
	t.Parallel()
	claims := filepath.Join(t.TempDir(), "nano-claims.jsonl")
	if err := os.WriteFile(claims, []byte("not json\n{\"hash\":\"AB\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	if _, err := composeNanoClaimsHandler(t, X402Config{NanoClaimsFile: claims}, &hits); err == nil {
		t.Fatal("ComposeHTTPRoutes() error = nil, want refusal of a claim log with an unreadable line")
	}
}

func TestComposeHTTPRoutesNanoRequireBinding(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	handler, err := composeNanoClaimsHandler(t, X402Config{NanoRequireBinding: true}, &hits)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	accepted := decodeNanoPaymentFixtureChallenge(t, nanoClaimsChallenge(t, handler))
	offer, ok := accepted.Extra["binding"].(map[string]any)
	if !ok {
		t.Fatalf("extra = %+v, want a binding offer", accepted.Extra)
	}
	nonce, _ := offer["nonce"].(string)
	if offer["scheme"] != nanoscheme.BindingScheme || offer["resource"] != "/paid" || len(nonce) != 32 {
		t.Fatalf("binding offer = %+v, want %s with a 32-hex nonce for /paid", offer, nanoscheme.BindingScheme)
	}
	if rec := payNanoPath(t, handler, accepted, "/paid/item", nanoClaimsTestPaidHash); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("bare block hash status = %d, want 402 when a binding is required", rec.Code)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

func TestComposeHTTPRoutesNanoOffersNoBindingByDefault(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	handler, err := composeNanoClaimsHandler(t, X402Config{}, &hits)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	accepted := decodeNanoPaymentFixtureChallenge(t, nanoClaimsChallenge(t, handler))
	if _, ok := accepted.Extra["binding"]; ok {
		t.Fatalf("extra = %+v, want no binding offer when x402_nano_require_binding is unset", accepted.Extra)
	}
}
