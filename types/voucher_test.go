package types

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReservationVoucherCanonicalBytes_StableAndExcludesSignature(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	sigBytes := []byte("some-signature-bytes")
	v := ReservationVoucher{
		ClientAddress: "0xdeadbeef",
		RelayURL:      "https://relay.example",
		IssuedAt:      t0,
		ExpiresAt:     t1,
		Signature:     sigBytes,
	}

	got := v.CanonicalBytes()
	if len(got) == 0 {
		t.Fatal("CanonicalBytes returned empty slice")
	}

	// Must be stable across calls.
	for i := 0; i < 5; i++ {
		again := v.CanonicalBytes()
		if string(again) != string(got) {
			t.Fatalf("CanonicalBytes is not stable: call 0 = %q, call %d = %q", got, i+1, again)
		}
	}

	// The canonical bytes must exactly equal the expected JSON — this
	// simultaneously validates field order, key names, timestamp encoding, and
	// signature exclusion without relying on substring searches.
	issuedNano := t0.UnixNano()
	expiresNano := t1.UnixNano()
	want := `{"client_address":"0xdeadbeef","relay_url":"https://relay.example","issued_at_unix_nano":` +
		strconv.FormatInt(issuedNano, 10) + `,"expires_at_unix_nano":` + strconv.FormatInt(expiresNano, 10) + `}`
	if string(got) != want {
		t.Errorf("CanonicalBytes mismatch:\n got:  %s\n want: %s", got, want)
	}

	// Belt-and-suspenders: confirm neither the signature JSON key nor the raw
	// signature payload bytes appear in any form.
	s := string(got)
	for _, forbidden := range []string{"signature", "Signature", string(sigBytes)} {
		if strings.Contains(s, forbidden) {
			t.Errorf("CanonicalBytes must not include %q; got: %s", forbidden, s)
		}
	}
}

func TestReservationVoucherCanonicalBytes_DifferentInputsDiffer(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	base := ReservationVoucher{
		ClientAddress: "0xdeadbeef",
		RelayURL:      "https://relay.example",
		IssuedAt:      t0,
		ExpiresAt:     t1,
	}

	differentClient := base
	differentClient.ClientAddress = "0xaaaa"

	differentRelay := base
	differentRelay.RelayURL = "https://other.example"

	differentExpiry := base
	differentExpiry.ExpiresAt = t1.Add(time.Minute)

	baseBytes := string(base.CanonicalBytes())
	for _, tc := range []struct {
		name    string
		voucher ReservationVoucher
	}{
		{"different_client", differentClient},
		{"different_relay", differentRelay},
		{"different_expiry", differentExpiry},
	} {
		if string(tc.voucher.CanonicalBytes()) == baseBytes {
			t.Errorf("%s: CanonicalBytes should differ from base but are equal", tc.name)
		}
	}
}
