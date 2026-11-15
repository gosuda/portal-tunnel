package pgns

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

const (
	MaxBatchSize     = 1024
	MaxIssuedAtLag   = uint64(300)
	MaxIssuedAtLead  = uint64(60)
	PoWDifficultyApp = 24
	PoWDifficultyID  = 18
)

var (
	// ErrTransitionInvalid marks any LeafTx that violates state-transition rules.
	ErrTransitionInvalid = errors.New("pgns: invalid state transition")
	// ErrInvalidPoW marks an insufficient proof-of-work nonce.
	ErrInvalidPoW = errors.New("pgns: insufficient proof of work")
)

// LeadingZeroBits returns the number of leading zero bits in digest (0..256).
func LeadingZeroBits(digest [32]byte) int {
	total := 0
	for _, b := range digest {
		if b == 0 {
			total += 8
			continue
		}
		return total + bits.LeadingZeros8(b)
	}
	return total
}

// PoWDigest returns SHA256("portal-pgns-pow-v1\x00" || txType || canonicalLeaf || uint64_be(nonce)).
func PoWDigest(txType uint8, canonicalLeaf []byte, nonce uint64) [32]byte {
	buf := buildPoWBuffer(txType, canonicalLeaf)
	binary.BigEndian.PutUint64(buf[len(buf)-8:], nonce)
	return sha256.Sum256(buf)
}

func buildPoWBuffer(txType uint8, canonicalLeaf []byte) []byte {
	buf := make([]byte, 0, len(powDomain)+1+len(canonicalLeaf)+8)
	buf = append(buf, powDomain...)
	buf = append(buf, txType)
	buf = append(buf, canonicalLeaf...)
	return append(buf, 0, 0, 0, 0, 0, 0, 0, 0)
}

// VerifyPoW checks that PoWDigest has at least requiredBits leading zero bits.
func VerifyPoW(txType uint8, canonicalLeaf []byte, nonce uint64, requiredBits int) bool {
	return LeadingZeroBits(PoWDigest(txType, canonicalLeaf, nonce)) >= requiredBits
}

// MinePoW searches nonces from 0 upward for a PoW solution meeting requiredBits.
func MinePoW(txType uint8, canonicalLeaf []byte, requiredBits int) uint64 {
	buf := buildPoWBuffer(txType, canonicalLeaf)
	nonceSlice := buf[len(buf)-8:]
	for nonce := uint64(0); ; nonce++ {
		binary.BigEndian.PutUint64(nonceSlice, nonce)
		if LeadingZeroBits(sha256.Sum256(buf)) >= requiredBits {
			return nonce
		}
	}
}

// RequiredPoWDifficulty returns the PoW difficulty in bits for a transaction and class,
// or 0 if no PoW is required.
func RequiredPoWDifficulty(txType uint8, class FQDNClass) int {
	if txType != TxTypeCreate && txType != TxTypeReclaim {
		return 0
	}
	if class == ClassSelfCertifying {
		return PoWDifficultyID
	}
	return PoWDifficultyApp
}

// ValidateTransition enforces all per-key PGNS state transition rules for one LeafTx
// at witness/epoch timestamp in zone.
func ValidateTransition(prev *PortalLeafRecord, tx LeafTx, timestamp uint64, zone string) error {
	parsed, err := tx.Leaf.ValidateInZone(zone)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTransitionInvalid, err)
	}
	if err := validateTransitionTimestamps(tx.Leaf, timestamp); err != nil {
		return err
	}
	canonicalLeaf, err := tx.Leaf.MarshalCanonical()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTransitionInvalid, err)
	}
	if err := verifyTxOwnerSig(tx, canonicalLeaf); err != nil {
		return err
	}
	switch tx.TxType {
	case TxTypeCreate:
		return validateCreate(prev, tx, canonicalLeaf, parsed)
	case TxTypeUpdate:
		return validateUpdate(prev, tx, parsed, timestamp)
	case TxTypeColdRecovery:
		return validateColdRecovery(prev, tx, canonicalLeaf, parsed, timestamp)
	case TxTypeReclaim:
		return validateReclaim(prev, tx, canonicalLeaf, parsed, timestamp)
	default:
		return fmt.Errorf("%w: unsupported tx_type %d", ErrTransitionInvalid, tx.TxType)
	}
}

func validateTransitionTimestamps(leaf PortalLeafRecord, timestamp uint64) error {
	if leaf.IssuedAt > math.MaxUint64-MaxLeafTTL {
		return fmt.Errorf("%w: issued_at overflow", ErrTransitionInvalid)
	}
	if timestamp > leaf.IssuedAt && timestamp-leaf.IssuedAt > MaxIssuedAtLag {
		return fmt.Errorf("%w: issued_at too old for epoch timestamp", ErrTransitionInvalid)
	}
	if leaf.IssuedAt > timestamp && leaf.IssuedAt-timestamp > MaxIssuedAtLead {
		return fmt.Errorf("%w: issued_at too far in future", ErrTransitionInvalid)
	}
	if leaf.ExpiresAt <= timestamp {
		return fmt.Errorf("%w: expires_at must exceed epoch timestamp", ErrTransitionInvalid)
	}
	if leaf.ExpiresAt <= leaf.IssuedAt || leaf.ExpiresAt-leaf.IssuedAt > MaxLeafTTL {
		return fmt.Errorf("%w: invalid validity span", ErrTransitionInvalid)
	}
	return nil
}

func verifyTxOwnerSig(tx LeafTx, canonicalLeaf []byte) error {
	ownerPub, err := identity.ParseSecp256k1CompressedPubKey33(tx.Leaf.OwnerPubKey)
	if err != nil {
		return fmt.Errorf("%w: owner_pubkey: %w", ErrTransitionInvalid, err)
	}
	payload := LeafTxOwnerSigningPayload(tx.TxType, tx.PoWNonce, canonicalLeaf)
	if err := identity.VerifySHA256Secp256k1LowSRaw64(payload, tx.OwnerSig[:], ownerPub); err != nil {
		return fmt.Errorf("%w: invalid owner_sig: %w", ErrTransitionInvalid, err)
	}
	return nil
}

func validateCreate(prev *PortalLeafRecord, tx LeafTx, canonicalLeaf []byte, parsed ParsedFQDN) error {
	if prev != nil {
		return fmt.Errorf("%w: create requires empty prior leaf", ErrTransitionInvalid)
	}
	if tx.Leaf.Seq != 1 {
		return fmt.Errorf("%w: create seq must be 1", ErrTransitionInvalid)
	}
	diff := RequiredPoWDifficulty(TxTypeCreate, parsed.Class)
	if !VerifyPoW(TxTypeCreate, canonicalLeaf, tx.PoWNonce, diff) {
		return fmt.Errorf("%w: need %d leading zero bits", ErrInvalidPoW, diff)
	}
	if parsed.Class == ClassSelfCertifying {
		tag, err := DeriveIDTag(tx.Leaf.OwnerPubKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTransitionInvalid, err)
		}
		if tag != parsed.IDTag {
			return fmt.Errorf("%w: owner_pubkey id-tag %s != fqdn id-tag %s", ErrTransitionInvalid, tag, parsed.IDTag)
		}
		if tx.Leaf.RecoveryKeyHash != ([32]byte{}) {
			return fmt.Errorf("%w: self-certifying leaf cannot set recovery_key_hash", ErrTransitionInvalid)
		}
	}
	return nil
}

func validateUpdate(prev *PortalLeafRecord, tx LeafTx, parsed ParsedFQDN, timestamp uint64) error {
	if prev == nil {
		return fmt.Errorf("%w: update requires existing leaf", ErrTransitionInvalid)
	}
	if tx.PoWNonce != 0 {
		return fmt.Errorf("%w: update pow_nonce must be 0", ErrTransitionInvalid)
	}
	if parsed.Class == ClassFriendlyAlias && isPastReclaimGrace(prev.ExpiresAt, timestamp) {
		return fmt.Errorf("%w: leaf expired past reclaim grace window", ErrTransitionInvalid)
	}
	if prev.Seq == math.MaxUint64 || tx.Leaf.Seq != prev.Seq+1 {
		return fmt.Errorf("%w: update seq %d must equal prev.seq+1 (%d)", ErrTransitionInvalid, tx.Leaf.Seq, prev.Seq+1)
	}
	if tx.Leaf.OwnerPubKey != prev.OwnerPubKey {
		return fmt.Errorf("%w: update cannot change owner_pubkey", ErrTransitionInvalid)
	}
	if prev.RecoveryKeyHash != ([32]byte{}) && tx.Leaf.RecoveryKeyHash != prev.RecoveryKeyHash {
		return fmt.Errorf("%w: update cannot alter or clear existing recovery_key_hash", ErrTransitionInvalid)
	}
	return nil
}

func validateColdRecovery(prev *PortalLeafRecord, tx LeafTx, canonicalLeaf []byte, parsed ParsedFQDN, timestamp uint64) error {
	if parsed.Class != ClassFriendlyAlias {
		return fmt.Errorf("%w: cold recovery supported only on *.app", ErrTransitionInvalid)
	}
	if prev == nil {
		return fmt.Errorf("%w: cold recovery requires existing leaf", ErrTransitionInvalid)
	}
	if prev.RecoveryKeyHash == ([32]byte{}) {
		return fmt.Errorf("%w: no recovery_key_hash registered", ErrTransitionInvalid)
	}
	if tx.PoWNonce != 0 {
		return fmt.Errorf("%w: cold recovery pow_nonce must be 0", ErrTransitionInvalid)
	}
	if isPastReclaimGrace(prev.ExpiresAt, timestamp) {
		return fmt.Errorf("%w: leaf expired past reclaim grace window", ErrTransitionInvalid)
	}
	coldHash, err := RecoveryKeyHash(tx.RecoveryPubKey)
	if err != nil {
		return fmt.Errorf("%w: recovery_pubkey: %w", ErrTransitionInvalid, err)
	}
	if coldHash != prev.RecoveryKeyHash {
		return fmt.Errorf("%w: recovery_pubkey does not match prev.recovery_key_hash", ErrTransitionInvalid)
	}
	coldPub, err := identity.ParseSecp256k1CompressedPubKey33(tx.RecoveryPubKey)
	if err != nil {
		return fmt.Errorf("%w: recovery_pubkey: %w", ErrTransitionInvalid, err)
	}
	recPayload := LeafTxRecoverySigningPayload(canonicalLeaf)
	if err := identity.VerifySHA256Secp256k1LowSRaw64(recPayload, tx.RecoverySig[:], coldPub); err != nil {
		return fmt.Errorf("%w: invalid recovery_sig: %w", ErrTransitionInvalid, err)
	}
	if prev.Seq > math.MaxUint64-ColdRecoveryMaxSeqJump {
		return fmt.Errorf("%w: prev.seq overflow on cold recovery", ErrTransitionInvalid)
	}
	if tx.Leaf.Seq <= prev.Seq || tx.Leaf.Seq-prev.Seq > ColdRecoveryMaxSeqJump {
		return fmt.Errorf("%w: cold recovery seq %d out of range (%d, %d]", ErrTransitionInvalid, tx.Leaf.Seq, prev.Seq, prev.Seq+ColdRecoveryMaxSeqJump)
	}
	return nil
}

func validateReclaim(prev *PortalLeafRecord, tx LeafTx, canonicalLeaf []byte, parsed ParsedFQDN, timestamp uint64) error {
	if parsed.Class != ClassFriendlyAlias {
		return fmt.Errorf("%w: reclaim supported only on *.app", ErrTransitionInvalid)
	}
	if prev == nil {
		return fmt.Errorf("%w: reclaim requires prior leaf", ErrTransitionInvalid)
	}
	if !isPastReclaimGrace(prev.ExpiresAt, timestamp) {
		return fmt.Errorf("%w: reclaim before grace period expiry", ErrTransitionInvalid)
	}
	if prev.Seq == math.MaxUint64 || tx.Leaf.Seq != prev.Seq+1 {
		return fmt.Errorf("%w: reclaim seq %d must equal prev.seq+1", ErrTransitionInvalid, tx.Leaf.Seq)
	}
	if !VerifyPoW(TxTypeReclaim, canonicalLeaf, tx.PoWNonce, PoWDifficultyApp) {
		return fmt.Errorf("%w: reclaim requires %d PoW bits", ErrInvalidPoW, PoWDifficultyApp)
	}
	return nil
}

func isPastReclaimGrace(expiresAt, timestamp uint64) bool {
	if expiresAt > math.MaxUint64-ReclaimGrace {
		return false
	}
	return timestamp > expiresAt+ReclaimGrace
}
