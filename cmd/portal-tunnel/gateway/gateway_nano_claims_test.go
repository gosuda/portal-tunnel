package gateway

import (
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	nanoscheme "github.com/gosuda/x402-facilitator/scheme/nano"
	"golang.org/x/crypto/blake2b"
)

const (
	nanoClaimsTestHashA = "ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113"
	nanoClaimsTestHashB = "0B5E2B7F6B4A0A9B6F1D3C2E4A5B6C7D8E9F0A1B2C3D4E5F60718293A4B5C6D7"
	nanoClaimsTestHashC = "7D6C5B4A39281706F5E4D3C2B1A09F8E7D6C5B4A39281706F5E4D3C2B1A09F8E"
)

// These Nano RPC endpoints are never dialed: composing routes and answering
// an unpaid request with a 402 only build the gates.
var nanoClaimsTestEndpoints = []string{"https://rpc-a.invalid", "https://rpc-b.invalid"}

func nanoClaimsTestRoutes(prefixes ...string) []ExposedHTTPRoute {
	routes := make([]ExposedHTTPRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		routes = append(routes, ExposedHTTPRoute{Prefix: prefix, Upstream: "http://127.0.0.1:1", Amount: "0.01"})
	}
	return routes
}

func writeNanoClaimLog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nano-claims.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenNanoClaimLogKeepsFinalRecordWithoutNewline(t *testing.T) {
	t.Parallel()
	path := writeNanoClaimLog(t, `{"hash":"`+nanoClaimsTestHashA+`","at":"2026-11-13T00:00:00Z"}`+"\n"+
		`{"hash":"`+nanoClaimsTestHashB+`","at":"2026-11-13T00:00:01Z"}`)

	claims, err := openNanoClaimLog(path)
	if err != nil {
		t.Fatalf("openNanoClaimLog() error = %v", err)
	}
	if !claims.Claim(nanoClaimsTestHashC) {
		t.Fatal("Claim() of a new block = false, want true")
	}
	if err := claims.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openNanoClaimLog(path)
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	for _, hash := range []string{nanoClaimsTestHashA, nanoClaimsTestHashB, nanoClaimsTestHashC} {
		if !reopened.Spent(hash) {
			t.Errorf("block %s is spendable again after reopen", hash)
		}
	}
}

func TestOpenNanoClaimLogDropsTornFinalLine(t *testing.T) {
	t.Parallel()
	path := writeNanoClaimLog(t, `{"hash":"`+nanoClaimsTestHashA+`"}`+"\n"+`{"hash":"`+nanoClaimsTestHashB[:20])

	claims, err := openNanoClaimLog(path)
	if err != nil {
		t.Fatalf("openNanoClaimLog() error = %v", err)
	}
	if !claims.Spent(nanoClaimsTestHashA) || claims.Spent(nanoClaimsTestHashB) {
		t.Fatal("want the complete record spent and the torn one ignored")
	}
	if !claims.Claim(nanoClaimsTestHashC) {
		t.Fatal("Claim() of a new block = false, want true")
	}
	if err := claims.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openNanoClaimLog(path)
	if err != nil {
		t.Fatalf("reopen after a torn write error = %v", err)
	}
	defer reopened.Close()
	if !reopened.Spent(nanoClaimsTestHashA) || !reopened.Spent(nanoClaimsTestHashC) {
		t.Fatal("complete records are spendable again after reopen")
	}
}

func TestComposeHTTPRoutesNanoClaimsFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nano-claims.jsonl")
	contract := X402Config{Network: "nano:mainnet", PayTo: nanoTestPayTo, Endpoints: nanoClaimsTestEndpoints, NanoClaimsFile: path}
	gw, err := ComposeHTTPRoutes(nanoClaimsTestRoutes("/paid"), contract)
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("claim log not created: %v", err)
	}
	// Windows has no Unix permission bits to check.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("claim log mode = %o, want 600", perm)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := os.WriteFile(path, []byte("not json\n{\"hash\":\"AB\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ComposeHTTPRoutes(nanoClaimsTestRoutes("/paid"), contract); err == nil {
		t.Fatal("ComposeHTTPRoutes() error = nil, want refusal of a claim log with an unreadable line")
	}
}

// nanoTestPayer holds a Nano account key. Nano signs with Ed25519 using
// BLAKE2b-512 in place of SHA-512.
type nanoTestPayer struct {
	scalar  *edwards25519.Scalar
	prefix  []byte
	public  []byte
	address string
}

func newNanoTestPayer(t *testing.T, private []byte) nanoTestPayer {
	t.Helper()
	expanded := blake2b.Sum512(private)
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(expanded[:32])
	if err != nil {
		t.Fatal(err)
	}
	public := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	checksum, err := blake2b.New(5, nil)
	if err != nil {
		t.Fatal(err)
	}
	checksum.Write(public)
	sum := checksum.Sum(nil)
	slices.Reverse(sum)
	return nanoTestPayer{
		scalar: scalar, prefix: expanded[32:], public: public,
		address: "nano_" + nanoTestBase32(public, 52) + nanoTestBase32(sum, 8),
	}
}

func nanoTestBase32(data []byte, chars int) string {
	value, digit, mask := new(big.Int).SetBytes(data), new(big.Int), big.NewInt(31)
	out := make([]byte, chars)
	for i := chars - 1; i >= 0; i-- {
		out[i] = nanoAddressAlphabet[digit.And(value, mask).Int64()]
		value.Rsh(value, 5)
	}
	return string(out)
}

func (p nanoTestPayer) sign(t *testing.T, msg []byte) string {
	t.Helper()
	digest := func(parts ...[]byte) *edwards25519.Scalar {
		h, err := blake2b.New512(nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range parts {
			h.Write(part)
		}
		s, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r := digest(p.prefix, msg)
	commitment := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	k := digest(commitment, p.public, msg)
	s := new(edwards25519.Scalar).MultiplyAdd(k, p.scalar, r)
	return strings.ToUpper(hex.EncodeToString(append(commitment, s.Bytes()...)))
}

func TestComposeHTTPRoutesNanoBindingOfferAcceptsPayerSignature(t *testing.T) {
	t.Parallel()
	gw, err := ComposeHTTPRoutes(nanoClaimsTestRoutes("/paid", "/also-paid"), X402Config{
		Network: "nano:mainnet", PayTo: nanoTestPayTo, Endpoints: nanoClaimsTestEndpoints, NanoRequireBinding: true,
	})
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	offer := func(path string) (nonce, resource string) {
		t.Helper()
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil))
		if rec.Code != http.StatusPaymentRequired {
			t.Fatalf("unpaid status = %d, want 402", rec.Code)
		}
		binding, ok := decodeNanoPaymentFixtureChallenge(t, rec).Extra["binding"].(map[string]any)
		if !ok || binding["scheme"] != nanoscheme.BindingScheme {
			t.Fatalf("binding offer = %+v, want %s", binding, nanoscheme.BindingScheme)
		}
		nonce, _ = binding["nonce"].(string)
		resource, _ = binding["resource"].(string)
		return nonce, resource
	}
	nonce, resource := offer("/paid/item")
	otherNonce, otherResource := offer("/also-paid/item")
	if len(nonce) != 32 || resource != "/paid" || otherResource != "/also-paid" || nonce == otherNonce {
		t.Fatalf("offers = (%q, %q) and (%q, %q), want a fresh 32-hex nonce per route", nonce, resource, otherNonce, otherResource)
	}

	// The facilitator verifies the binding against the paying account read
	// from the ledger; this is the check it runs on a payment to /paid.
	payer := newNanoTestPayer(t, []byte("portal-tunnel nano binding payer"))
	msg, err := nanoscheme.BindingMessage(nanoClaimsTestHashA, nonce, resource, nanoTestPayTo)
	if err != nil {
		t.Fatal(err)
	}
	sig := payer.sign(t, msg)
	if err := nanoscheme.VerifyBinding(payer.address, msg, sig); err != nil {
		t.Fatalf("payer's signature over the /paid offer refused: %v", err)
	}
	otherMsg, err := nanoscheme.BindingMessage(nanoClaimsTestHashA, otherNonce, otherResource, nanoTestPayTo)
	if err != nil {
		t.Fatal(err)
	}
	if err := nanoscheme.VerifyBinding(payer.address, otherMsg, sig); !errors.Is(err, nanoscheme.ErrBindingInvalid) {
		t.Fatalf("/paid signature on the /also-paid offer: err = %v, want %v", err, nanoscheme.ErrBindingInvalid)
	}
	stranger := newNanoTestPayer(t, []byte("portal-tunnel nano other account"))
	if err := nanoscheme.VerifyBinding(stranger.address, msg, sig); !errors.Is(err, nanoscheme.ErrBindingInvalid) {
		t.Fatalf("signature accepted for an account that did not pay: err = %v, want %v", err, nanoscheme.ErrBindingInvalid)
	}
}

func TestComposeHTTPRoutesNanoOffersNoBindingByDefault(t *testing.T) {
	t.Parallel()
	gw, err := ComposeHTTPRoutes(nanoClaimsTestRoutes("/paid"), X402Config{
		Network: "nano:mainnet", PayTo: nanoTestPayTo, Endpoints: nanoClaimsTestEndpoints,
	})
	if err != nil {
		t.Fatalf("ComposeHTTPRoutes() error = %v", err)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/paid/item", nil))
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("unpaid status = %d, want 402", rec.Code)
	}
	if accepted := decodeNanoPaymentFixtureChallenge(t, rec); accepted.Extra["binding"] != nil {
		t.Fatalf("extra = %+v, want no binding offer when x402_nano_require_binding is unset", accepted.Extra)
	}
}
