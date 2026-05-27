package utils

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrHTPCongruence is returned when the HTP modular congruence check fails.
	ErrHTPCongruence = errors.New("htp: congruence check failed")
	// ErrHTPReplay is returned when a packet nonce is not monotonically increasing.
	ErrHTPReplay = errors.New("htp: replay attack detected")
	// ErrHTPTemporal is returned when the packet timestamp drift exceeds 1 second.
	ErrHTPTemporal = errors.New("htp: temporal delta exceeded")
)

// HTPVerifier holds server-side state for HTP packet verification.
type HTPVerifier struct {
	S        uint32
	ShiftK   uint8
	mu       sync.Mutex
	maxNonce uint32
}

// NewHTPVerifier creates a verifier with the shared seed S and rotation parameter k.
func NewHTPVerifier(S uint32, shiftK uint8) *HTPVerifier {
	return &HTPVerifier{S: S, ShiftK: shiftK}
}

// ObfuscatePacket applies a circular left rotation to a 64-bit raw value.
// This is the client-side outbound obfuscation step.
func ObfuscatePacket(vRaw uint64, k uint8) uint64 {
	s := uint64(k) % 64
	if s == 0 {
		return vRaw
	}
	return (vRaw << s) | (vRaw >> (64 - s))
}

// DeobfuscatePacket applies the inverse circular right rotation.
// This is the server-side inbound decoding step.
func DeobfuscatePacket(vRot uint64, k uint8) uint64 {
	s := uint64(k) % 64
	if s == 0 {
		return vRot
	}
	return (vRot >> s) | (vRot << (64 - s))
}

// PackHTPBlock assembles the 64-bit transmission block.
//   Bits [63:32] : timestamp (uint32)
//   Bits [31:8]  : nonce     (uint24)
//   Bits [7:0]   : htpCheck  (uint8)
func PackHTPBlock(timestamp uint32, nonce uint32, htpCheck uint8) uint64 {
	return (uint64(timestamp) << 32) | ((uint64(nonce) & 0xFFFFFF) << 8) | uint64(htpCheck)
}

// UnpackHTPBlock disassembles the 64-bit transmission block.
func UnpackHTPBlock(vRaw uint64) (timestamp uint32, nonce uint32, htpCheck uint8) {
	timestamp = uint32(vRaw >> 32)
	nonce = uint32((vRaw >> 8) & 0xFFFFFF)
	htpCheck = uint8(vRaw & 0xFF)
	return
}

// splitmix64 is a fast 64-bit pseudo-random generator used to expand a seed
// into the 12 uint32 vertices of the HTP grid.
func splitmix64(x uint64) uint64 {
	z := x + 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	z = z ^ (z >> 31)
	return z
}

// htpVertices deterministically expands a seed into 12 uint32 vertices.
// The vertex layout follows the 3-hexagon interlocking matrix:
//
//	H1: v0, v1, v2, v3, v4, v5
//	H2: v4, v5, v6, v7, v8, v9
//	H3: v2, v3, v4, v6, v10, v11
func htpVertices(seed uint64) [12]uint32 {
	var v [12]uint32
	x := seed
	for i := 0; i < 12; i++ {
		x = splitmix64(x)
		v[i] = uint32(x)
	}
	return v
}

// ComputeHTPCheck calculates the 8-bit HTP congruence token.
// The payload is the 56-bit value formed by timestamp and nonce.
// S is the 32-bit seed shared during the TLS 1.3 handshake.
func ComputeHTPCheck(timestamp uint32, nonce uint32, S uint32) uint8 {
	raw := (uint64(timestamp) << 32) | ((uint64(nonce) & 0xFFFFFF) << 8)
	seed := raw ^ uint64(S)
	v := htpVertices(seed)

	// Compute the three hexagon sums modulo 2^32 (native uint32 overflow).
	h1 := v[0] + v[1] + v[2] + v[3] + v[4] + v[5]
	h2 := v[4] + v[5] + v[6] + v[7] + v[8] + v[9]
	h3 := v[2] + v[3] + v[4] + v[6] + v[10] + v[11]

	// The 8-bit token encodes the combined congruence state of all
	// three hexagons relative to the seed S.
	check := h1 ^ h2 ^ h3 ^ S
	return uint8(check & 0xFF)
}

// VerifyHTPPacket performs full inbound verification:
//   1. Reconstruct the HTP grid and verify the modular congruence.
//   2. Ensure the nonce is strictly greater than the highest seen nonce.
//   3. Ensure |serverTime - packetTime| <= 1 second.
func (v *HTPVerifier) VerifyHTPPacket(vRot uint64, now time.Time) error {
	vRaw := DeobfuscatePacket(vRot, v.ShiftK)
	timestamp, nonce, htpCheck := UnpackHTPBlock(vRaw)

	// Mathematical Congruence Check.
	if ComputeHTPCheck(timestamp, nonce, v.S) != htpCheck {
		return ErrHTPCongruence
	}

	// Anti-Replay Verification.
	v.mu.Lock()
	if nonce <= v.maxNonce {
		v.mu.Unlock()
		return ErrHTPReplay
	}
	v.maxNonce = nonce
	v.mu.Unlock()

	// Temporal Delta Validation.
	pktTime := time.Unix(int64(timestamp), 0)
	delta := now.Sub(pktTime)
	if delta < 0 {
		delta = -delta
	}
	if delta > time.Second {
		return ErrHTPTemporal
	}

	return nil
}
