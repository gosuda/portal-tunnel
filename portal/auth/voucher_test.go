package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// freshVoucher returns a basic ReservationVoucher (unsigned) for use in tests.
func freshVoucher(clientAddr, relayURL string) types.ReservationVoucher {
	now := time.Now().UTC()
	return types.ReservationVoucher{
		ClientAddress: clientAddr,
		RelayURL:      relayURL,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

// TestSignReservationVoucherRoundTrip signs a voucher and immediately verifies
// it against the same identity. Expects no error.
func TestSignReservationVoucherRoundTrip(t *testing.T) {
	id, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}

	v := freshVoucher("client-addr-roundtrip", "https://relay.example")
	signed, err := auth.SignReservationVoucher(v, id.PrivateKey)
	if err != nil {
		t.Fatalf("SignReservationVoucher() error = %v", err)
	}
	if len(signed.Signature) == 0 {
		t.Fatal("SignReservationVoucher() returned empty Signature")
	}

	if err := auth.VerifyReservationVoucher(signed, id.Address); err != nil {
		t.Fatalf("VerifyReservationVoucher() error = %v", err)
	}
}

// TestVerifyReservationVoucherWrongAddress signs with identity A but verifies
// against address B; expects an error containing "does not match".
func TestVerifyReservationVoucherWrongAddress(t *testing.T) {
	idA, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity(A) error = %v", err)
	}
	idB, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity(B) error = %v", err)
	}

	// Ensure the two identities are different.
	if idA.Address == idB.Address {
		t.Skip("ResolveSecp256k1Identity returned same address twice; cannot run wrong-address test")
	}

	v := freshVoucher("client-addr-wrong", "https://relay.example")
	signed, err := auth.SignReservationVoucher(v, idA.PrivateKey)
	if err != nil {
		t.Fatalf("SignReservationVoucher() error = %v", err)
	}

	err = auth.VerifyReservationVoucher(signed, idB.Address)
	if err == nil {
		t.Fatal("VerifyReservationVoucher() with wrong address returned nil error; want error")
	}
	if msg := err.Error(); !strings.Contains(msg, "does not match") {
		t.Fatalf("VerifyReservationVoucher() error %q does not contain %q", msg, "does not match")
	}
}

// TestVerifyReservationVoucherTampered signs, then mutates ExpiresAt, and
// verifies. Expects an error (recovered key will not match).
func TestVerifyReservationVoucherTampered(t *testing.T) {
	id, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}

	v := freshVoucher("client-addr-tamper", "https://relay.example")
	signed, err := auth.SignReservationVoucher(v, id.PrivateKey)
	if err != nil {
		t.Fatalf("SignReservationVoucher() error = %v", err)
	}

	// Tamper: move ExpiresAt one day forward.
	signed.ExpiresAt = signed.ExpiresAt.Add(24 * time.Hour)

	err = auth.VerifyReservationVoucher(signed, id.Address)
	if err == nil {
		t.Fatal("VerifyReservationVoucher() after tampering returned nil error; want error")
	}
}

// TestVerifyReservationVoucherUnsigned verifies an empty Signature field;
// expects an error containing "not signed".
func TestVerifyReservationVoucherUnsigned(t *testing.T) {
	id, err := utils.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatalf("ResolveSecp256k1Identity() error = %v", err)
	}

	v := freshVoucher("client-addr-unsigned", "https://relay.example")
	// Do NOT sign — Signature is nil.
	err = auth.VerifyReservationVoucher(v, id.Address)
	if err == nil {
		t.Fatal("VerifyReservationVoucher() unsigned returned nil error; want error")
	}
	if msg := err.Error(); !strings.Contains(msg, "not signed") {
		t.Fatalf("VerifyReservationVoucher() unsigned error %q does not contain %q", msg, "not signed")
	}
}
