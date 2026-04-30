package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// relayIdentityForTest mints a fresh secp256k1 identity for use in tests.
func relayIdentityForTest(t *testing.T) (privKey, address string) {
	t.Helper()
	id, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}
	return id.PrivateKey, id.Address
}

// postReserve performs a POST to handleAdminReserve and returns the response.
func postReserve(t *testing.T, privKey, address, body string, budget *atomic.Int64, max int64) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/reserve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleAdminReserve(rr, req, privKey, address, budget, max)
	return rr
}

// TestAdminReserveReturnsValidVoucher verifies that a well-formed POST returns
// 200 with a parseable signed voucher, and that the voucher verifies against
// the relay's address.
func TestAdminReserveReturnsValidVoucher(t *testing.T) {
	privKey, address := relayIdentityForTest(t)
	var budgetUsed atomic.Int64

	body := `{"client_address":"test-client","requested_duration_seconds":60}`
	rr := postReserve(t, privKey, address, body, &budgetUsed, 100)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var envelope types.APIEnvelope[types.ReservationVoucher]
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body: %s", err, rr.Body.String())
	}
	if !envelope.OK {
		t.Fatalf("envelope.OK = false; body: %s", rr.Body.String())
	}
	voucher := envelope.Data
	if len(voucher.Signature) == 0 {
		t.Fatal("voucher.Signature is empty; want a signed voucher")
	}

	if err := auth.VerifyReservationVoucher(voucher, address); err != nil {
		t.Fatalf("VerifyReservationVoucher() error = %v", err)
	}
}

// TestAdminReserveCapacityExhausted verifies that once the budget is consumed
// subsequent requests receive 503.
func TestAdminReserveCapacityExhausted(t *testing.T) {
	privKey, address := relayIdentityForTest(t)
	var budgetUsed atomic.Int64
	const budget = 2

	body := `{"client_address":"test-client","requested_duration_seconds":60}`

	rr1 := postReserve(t, privKey, address, body, &budgetUsed, budget)
	if rr1.Code != http.StatusOK {
		t.Fatalf("request 1: status = %d, want %d", rr1.Code, http.StatusOK)
	}

	rr2 := postReserve(t, privKey, address, body, &budgetUsed, budget)
	if rr2.Code != http.StatusOK {
		t.Fatalf("request 2: status = %d, want %d", rr2.Code, http.StatusOK)
	}

	rr3 := postReserve(t, privKey, address, body, &budgetUsed, budget)
	if rr3.Code != http.StatusServiceUnavailable {
		t.Fatalf("request 3: status = %d, want %d (capacity exhausted)", rr3.Code, http.StatusServiceUnavailable)
	}
}

// TestAdminReserveRequiresAuth verifies that the /admin/reserve route is gated
// behind authentication: a request without a valid session cookie returns 401.
// We test this via the serveAdmin dispatcher (which owns the auth gate) using a
// minimal Frontend with auth enabled.
func TestAdminReserveRequiresAuth(t *testing.T) {
	auth, err := newAdminAuth("test-secret-key")
	if err != nil {
		t.Fatalf("newAdminAuth() error = %v", err)
	}
	f := &Frontend{auth: auth}

	req := httptest.NewRequest(http.MethodPost, "/admin/reserve",
		strings.NewReader(`{"client_address":"c","requested_duration_seconds":60}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	f.serveAdmin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (unauthenticated request must be rejected)", rr.Code, http.StatusUnauthorized)
	}
}
