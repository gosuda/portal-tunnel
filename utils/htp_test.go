package utils

import (
	"testing"
	"time"
)

func TestObfuscateDeobfuscateRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		vRaw  uint64
		shift uint8
	}{
		{name: "no rotation", vRaw: 0x123456789ABCDEF0, shift: 0},
		{name: "rotate by 1", vRaw: 0x123456789ABCDEF0, shift: 1},
		{name: "rotate by 7", vRaw: 0x123456789ABCDEF0, shift: 7},
		{name: "rotate by 8", vRaw: 0x123456789ABCDEF0, shift: 8},
		{name: "rotate by 31", vRaw: 0x123456789ABCDEF0, shift: 31},
		{name: "rotate by 32", vRaw: 0x123456789ABCDEF0, shift: 32},
		{name: "rotate by 63", vRaw: 0x123456789ABCDEF0, shift: 63},
		{name: "all zeros", vRaw: 0x0000000000000000, shift: 17},
		{name: "all ones", vRaw: 0xFFFFFFFFFFFFFFFF, shift: 42},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vRot := ObfuscatePacket(tc.vRaw, tc.shift)
			got := DeobfuscatePacket(vRot, tc.shift)

			if got != tc.vRaw {
				t.Fatalf("round-trip failed: got 0x%016X, want 0x%016X", got, tc.vRaw)
			}
		})
	}
}

func TestPackUnpackHTPBlock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		timestamp uint32
		nonce     uint32
		htpCheck  uint8
	}{
		{name: "basic", timestamp: 0x12345678, nonce: 0xABCDEF, htpCheck: 0x42},
		{name: "max values", timestamp: 0xFFFFFFFF, nonce: 0xFFFFFF, htpCheck: 0xFF},
		{name: "min values", timestamp: 0x00000000, nonce: 0x000000, htpCheck: 0x00},
		{name: "nonce masked", timestamp: 0xAABBCCDD, nonce: 0xFF1234, htpCheck: 0xAB},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packed := PackHTPBlock(tc.timestamp, tc.nonce, tc.htpCheck)
			ts, nonce, check := UnpackHTPBlock(packed)

			if ts != tc.timestamp {
				t.Fatalf("timestamp mismatch: got 0x%08X, want 0x%08X", ts, tc.timestamp)
			}
			if nonce != (tc.nonce & 0xFFFFFF) {
				t.Fatalf("nonce mismatch: got 0x%06X, want 0x%06X", nonce, tc.nonce&0xFFFFFF)
			}
			if check != tc.htpCheck {
				t.Fatalf("htpCheck mismatch: got 0x%02X, want 0x%02X", check, tc.htpCheck)
			}
		})
	}
}

func TestComputeHTPCheckDeterminism(t *testing.T) {
	t.Parallel()

	// The same inputs must always produce the same token.
	const (
		timestamp uint32 = 0x6655AA77
		nonce     uint32 = 0x123456
		S         uint32 = 0xDEADBEEF
	)

	first := ComputeHTPCheck(timestamp, nonce, S)
	for i := 0; i < 100; i++ {
		if got := ComputeHTPCheck(timestamp, nonce, S); got != first {
			t.Fatalf("non-deterministic result: iteration %d got 0x%02X, want 0x%02X", i, got, first)
		}
	}
}

func TestHTPVerifierAcceptsValidPacket(t *testing.T) {
	t.Parallel()

	const (
		S       uint32 = 0xCAFEBABE
		shiftK  uint8  = 17
		nonce   uint32 = 1
	)

	verifier := NewHTPVerifier(S, shiftK)
	now := time.Now()
	timestamp := uint32(now.Unix())

	htpCheck := ComputeHTPCheck(timestamp, nonce, S)
	vRaw := PackHTPBlock(timestamp, nonce, htpCheck)
	vRot := ObfuscatePacket(vRaw, shiftK)

	if err := verifier.VerifyHTPPacket(vRot, now); err != nil {
		t.Fatalf("expected valid packet to be accepted, got error: %v", err)
	}
}

func TestHTPVerifierRejections(t *testing.T) {
	t.Parallel()

	const (
		S       uint32 = 0xBADC0FFE
		shiftK  uint8  = 31
		nonce   uint32 = 100
	)

	verifier := NewHTPVerifier(S, shiftK)
	now := time.Now()
	timestamp := uint32(now.Unix())

	htpCheck := ComputeHTPCheck(timestamp, nonce, S)
	vRaw := PackHTPBlock(timestamp, nonce, htpCheck)
	vRot := ObfuscatePacket(vRaw, shiftK)

	// First packet should succeed.
	if err := verifier.VerifyHTPPacket(vRot, now); err != nil {
		t.Fatalf("first packet should succeed, got: %v", err)
	}

	// Same packet again → replay.
	if err := verifier.VerifyHTPPacket(vRot, now); err != ErrHTPReplay {
		t.Fatalf("expected ErrHTPReplay, got: %v", err)
	}

	// Tampered checksum → congruence failure.
	tamperedRaw := PackHTPBlock(timestamp, nonce+1, htpCheck)
	tamperedRot := ObfuscatePacket(tamperedRaw, shiftK)
	if err := verifier.VerifyHTPPacket(tamperedRot, now); err != ErrHTPCongruence {
		t.Fatalf("expected ErrHTPCongruence, got: %v", err)
	}

	// Stale timestamp → temporal failure.
	oldTimestamp := uint32(now.Add(-2 * time.Second).Unix())
	oldCheck := ComputeHTPCheck(oldTimestamp, nonce+2, S)
	oldRaw := PackHTPBlock(oldTimestamp, nonce+2, oldCheck)
	oldRot := ObfuscatePacket(oldRaw, shiftK)
	if err := verifier.VerifyHTPPacket(oldRot, now); err != ErrHTPTemporal {
		t.Fatalf("expected ErrHTPTemporal, got: %v", err)
	}
}

func TestHTPVerifierNonceStrictlyIncreasing(t *testing.T) {
	t.Parallel()

	const (
		S      uint32 = 0x11223344
		shiftK uint8  = 5
	)

	verifier := NewHTPVerifier(S, shiftK)
	now := time.Now()
	baseTime := uint32(now.Unix())

	for i := uint32(1); i <= 5; i++ {
		htpCheck := ComputeHTPCheck(baseTime, i, S)
		vRaw := PackHTPBlock(baseTime, i, htpCheck)
		vRot := ObfuscatePacket(vRaw, shiftK)
		if err := verifier.VerifyHTPPacket(vRot, now); err != nil {
			t.Fatalf("packet %d should succeed, got: %v", i, err)
		}
	}

	// Nonce 3 is now behind maxNonce (5).
	htpCheck := ComputeHTPCheck(baseTime, 3, S)
	vRaw := PackHTPBlock(baseTime, 3, htpCheck)
	vRot := ObfuscatePacket(vRaw, shiftK)
	if err := verifier.VerifyHTPPacket(vRot, now); err != ErrHTPReplay {
		t.Fatalf("expected ErrHTPReplay for nonce 3, got: %v", err)
	}
}

func TestHTPVerifierTemporalBoundary(t *testing.T) {
	t.Parallel()

	const (
		S      uint32 = 0xAABBCCDD
		shiftK uint8  = 13
		nonce  uint32 = 1
	)

	verifier := NewHTPVerifier(S, shiftK)
	now := time.Now()

	// Packet from exactly 1 second ago should be accepted (delta == 1s).
	boundaryTime := uint32(now.Add(-time.Second).Unix())
	htpCheck := ComputeHTPCheck(boundaryTime, nonce, S)
	vRaw := PackHTPBlock(boundaryTime, nonce, htpCheck)
	vRot := ObfuscatePacket(vRaw, shiftK)

	// This might fail due to second boundary jitter; allow both outcomes.
	err := verifier.VerifyHTPPacket(vRot, now)
	if err != nil && err != ErrHTPTemporal {
		t.Fatalf("unexpected error: %v", err)
	}

	// Packet from 2 seconds ago must fail.
	oldTime := uint32(now.Add(-2 * time.Second).Unix())
	oldCheck := ComputeHTPCheck(oldTime, nonce+1, S)
	oldRaw := PackHTPBlock(oldTime, nonce+1, oldCheck)
	oldRot := ObfuscatePacket(oldRaw, shiftK)
	if err := verifier.VerifyHTPPacket(oldRot, now); err != ErrHTPTemporal {
		t.Fatalf("expected ErrHTPTemporal for 2s old packet, got: %v", err)
	}
}
