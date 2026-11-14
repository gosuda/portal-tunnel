package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// INV: SignSHA256Secp256k1LowSRaw64 outputs BIP-62 low-S signatures verified by both
// VerifySHA256Secp256k1LowSRaw64 and VerifySHA256Secp256k1Raw64; high-S malleated
// signatures (N - s) MUST be rejected by VerifySHA256Secp256k1LowSRaw64 while
// tampered payloads, keys, or lengths also fail.
func TestSecp256k1LowSSignatureInvariant(t *testing.T) {
	privBytes, err := hex.DecodeString("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d")
	if err != nil {
		t.Fatal(err)
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	pub := priv.PubKey()
	payload := []byte("portal-pgns-tx-v1\x00low-s-attack")

	sig, err := SignSHA256Secp256k1LowSRaw64(payload, priv)
	if err != nil {
		t.Fatalf("SignSHA256Secp256k1LowSRaw64: %v", err)
	}
	if err := VerifySHA256Secp256k1LowSRaw64(payload, sig, pub); err != nil {
		t.Fatalf("VerifySHA256Secp256k1LowSRaw64: %v", err)
	}
	if err := VerifySHA256Secp256k1Raw64(payload, sig, pub); err != nil {
		t.Fatalf("VerifySHA256Secp256k1Raw64: %v", err)
	}

	// Synthesize the malleable high-S twin (r, N - s).
	var highS secp256k1.ModNScalar
	if overflow := highS.SetByteSlice(sig[32:]); overflow || highS.IsZero() {
		t.Fatal("invalid s scalar")
	}
	highS.Negate()
	if !highS.IsOverHalfOrder() {
		t.Fatal("expected negated low-s to be over half order")
	}
	malleated := append([]byte(nil), sig...)
	highS.PutBytesUnchecked(malleated[32:])

	// Existing raw verifier preserves legacy behavior on high-S.
	if err := VerifySHA256Secp256k1Raw64(payload, malleated, pub); err != nil {
		t.Fatalf("expected legacy verifier to accept malleated twin: %v", err)
	}
	// Strict PGNS low-S verifier MUST reject the high-S twin.
	if err := VerifySHA256Secp256k1LowSRaw64(payload, malleated, pub); !errors.Is(err, errInvalidEs256kSignatureHighS) {
		t.Fatalf("VerifySHA256Secp256k1LowSRaw64(high-S) = %v, want %v", err, errInvalidEs256kSignatureHighS)
	}

	// Mutated payload fails verification.
	badPayload := append([]byte(nil), payload...)
	badPayload[len(badPayload)-1] ^= 0xff
	if err := VerifySHA256Secp256k1LowSRaw64(badPayload, sig, pub); !errors.Is(err, ErrSecp256k1SignatureInvalid) {
		t.Fatalf("VerifySHA256Secp256k1LowSRaw64(bad payload) = %v, want %v", err, ErrSecp256k1SignatureInvalid)
	}

	// Wrong public key fails verification.
	other := secp256k1.PrivKeyFromBytes(func() []byte { h := sha256.Sum256(privBytes); return h[:] }())
	if err := VerifySHA256Secp256k1LowSRaw64(payload, sig, other.PubKey()); !errors.Is(err, ErrSecp256k1SignatureInvalid) {
		t.Fatalf("VerifySHA256Secp256k1LowSRaw64(wrong key) = %v, want %v", err, ErrSecp256k1SignatureInvalid)
	}

	// Invalid compressed key prefix fails ParseSecp256k1CompressedPubKey33.
	var compressed [33]byte
	copy(compressed[:], pub.SerializeCompressed())
	compressed[0] = 0x04
	if _, err := ParseSecp256k1CompressedPubKey33(compressed); err == nil {
		t.Fatal("expected ParseSecp256k1CompressedPubKey33 to reject uncompressed prefix")
	}
}
