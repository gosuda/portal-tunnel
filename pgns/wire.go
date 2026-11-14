package pgns

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	LeafVersion            uint8  = 1
	FlagHTTP2              uint16 = 1 << 0
	FlagPersist01Enabled   uint16 = 1 << 1
	FlagsAllowedMask              = FlagHTTP2 | FlagPersist01Enabled
	MaxLeafTTL             uint64 = 604800 // 7 days
	ReclaimGrace           uint64 = 86400  // 24 hours
	ColdRecoveryMaxSeqJump uint64 = 65536
	MaxEndpoints                  = 8
	MaxACMEIssuerLen              = 64
	MaxACMEAccountURILen          = 160
	endpointWireSize              = 44

	TxTypeCreate       uint8 = 1
	TxTypeUpdate       uint8 = 2
	TxTypeColdRecovery uint8 = 3
	TxTypeReclaim      uint8 = 4

	txSignDomain       = "portal-pgns-tx-v1\x00"
	recoverySignDomain = "portal-pgns-recover-v1\x00"
	powDomain          = "portal-pgns-pow-v1\x00"
)

var (
	// ErrInvalidWire marks malformed or non-canonical binary wire encodings.
	ErrInvalidWire = errors.New("pgns: invalid wire encoding")
	// ErrInvalidLeaf marks a semantically invalid PortalLeafRecord field.
	ErrInvalidLeaf = errors.New("pgns: invalid leaf record")
	// ErrInvalidEndpoint marks an invalid or non-public relay endpoint.
	ErrInvalidEndpoint     = errors.New("pgns: invalid endpoint")
	errOwnerKeyRequired    = errors.New("pgns: owner private key is required")
	errRecoveryKeyRequired = errors.New("pgns: recovery private key is required")
)

// Endpoint describes one relay ingress target published inside a PortalLeafRecord.
type Endpoint struct {
	RelayID  [20]byte
	IPv4     [4]byte
	IPv6     [16]byte
	Port     uint16
	Priority uint16
}

// PortalLeafRecord is the canonical leaf state stored in the 256-bit Portal Name Tree.
type PortalLeafRecord struct {
	Version           uint8
	Flags             uint16
	FQDN              string
	Seq               uint64
	IssuedAt          uint64
	ExpiresAt         uint64
	OwnerPubKey       [33]byte
	RecoveryKeyHash   [32]byte
	TLSSPKISHA256     [32]byte
	NextTLSSPKISHA256 [32]byte
	ACMECAIssuer      string
	ACMEAccountURI    string
	ACMEDNS01Digest   [32]byte
	Endpoints         []Endpoint
}

// LeafTx is a signed state transition submitted to the PGNS sequencer and verified by witnesses.
type LeafTx struct {
	TxType         uint8
	Leaf           PortalLeafRecord
	PoWNonce       uint64
	RecoveryPubKey [33]byte
	RecoverySig    [64]byte
	OwnerSig       [64]byte
}

// MarshalCanonical serializes a PortalLeafRecord into canonical big-endian wire bytes
// after verifying structural field constraints.
func (r PortalLeafRecord) MarshalCanonical() ([]byte, error) {
	if err := r.ValidateStructure(); err != nil {
		return nil, err
	}
	size := 1 + 2 + 1 + len(r.FQDN) + 8 + 8 + 8 + 33 + 32 + 32 + 32 +
		1 + len(r.ACMECAIssuer) + 1 + len(r.ACMEAccountURI) + 32 +
		1 + len(r.Endpoints)*endpointWireSize
	buf := make([]byte, 0, size)
	buf = append(buf, r.Version)
	buf = binary.BigEndian.AppendUint16(buf, r.Flags)
	buf = appendUint8String(buf, r.FQDN)
	buf = binary.BigEndian.AppendUint64(buf, r.Seq)
	buf = binary.BigEndian.AppendUint64(buf, r.IssuedAt)
	buf = binary.BigEndian.AppendUint64(buf, r.ExpiresAt)
	buf = append(buf, r.OwnerPubKey[:]...)
	buf = append(buf, r.RecoveryKeyHash[:]...)
	buf = append(buf, r.TLSSPKISHA256[:]...)
	buf = append(buf, r.NextTLSSPKISHA256[:]...)
	buf = appendUint8String(buf, r.ACMECAIssuer)
	buf = appendUint8String(buf, r.ACMEAccountURI)
	buf = append(buf, r.ACMEDNS01Digest[:]...)
	buf = append(buf, uint8(len(r.Endpoints)))
	for _, ep := range r.Endpoints {
		buf = append(buf, ep.RelayID[:]...)
		buf = append(buf, ep.IPv4[:]...)
		buf = append(buf, ep.IPv6[:]...)
		buf = binary.BigEndian.AppendUint16(buf, ep.Port)
		buf = binary.BigEndian.AppendUint16(buf, ep.Priority)
	}
	return buf, nil
}

// UnmarshalCanonicalLeaf decodes exact canonical big-endian bytes into a PortalLeafRecord
// and enforces structural invariants, rejecting any trailing bytes.
func UnmarshalCanonicalLeaf(data []byte) (PortalLeafRecord, error) {
	leaf, consumed, err := decodeCanonicalLeafPrefix(data)
	if err != nil {
		return PortalLeafRecord{}, err
	}
	if consumed != len(data) {
		return PortalLeafRecord{}, fmt.Errorf("%w: %d trailing bytes", ErrInvalidWire, len(data)-consumed)
	}
	if err := leaf.ValidateStructure(); err != nil {
		return PortalLeafRecord{}, err
	}
	return leaf, nil
}

func decodeCanonicalLeafPrefix(data []byte) (PortalLeafRecord, int, error) {
	var leaf PortalLeafRecord
	off := 0
	var ok bool
	if leaf.Version, off, ok = readUint8(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated version", ErrInvalidWire)
	}
	if leaf.Flags, off, ok = readUint16(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated flags", ErrInvalidWire)
	}
	if leaf.FQDN, off, ok = readUint8String(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated fqdn", ErrInvalidWire)
	}
	if leaf.Seq, off, ok = readUint64(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated seq", ErrInvalidWire)
	}
	if leaf.IssuedAt, off, ok = readUint64(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated issued_at", ErrInvalidWire)
	}
	if leaf.ExpiresAt, off, ok = readUint64(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated expires_at", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, leaf.OwnerPubKey[:]); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated owner_pubkey", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, leaf.RecoveryKeyHash[:]); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated recovery_key_hash", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, leaf.TLSSPKISHA256[:]); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated tls_spki_sha256", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, leaf.NextTLSSPKISHA256[:]); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated next_tls_spki_sha256", ErrInvalidWire)
	}
	if leaf.ACMECAIssuer, off, ok = readUint8String(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated acme_caa_issuer", ErrInvalidWire)
	}
	if leaf.ACMEAccountURI, off, ok = readUint8String(data, off); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated acme_account_uri", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, leaf.ACMEDNS01Digest[:]); !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated acme_dns01_digest", ErrInvalidWire)
	}
	count, nextOff, ok := readUint8(data, off)
	if !ok {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated endpoint count", ErrInvalidWire)
	}
	off = nextOff
	if count == 0 || count > MaxEndpoints {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: invalid endpoint count %d", ErrInvalidLeaf, count)
	}
	if len(data)-off < int(count)*endpointWireSize {
		return PortalLeafRecord{}, 0, fmt.Errorf("%w: truncated endpoints", ErrInvalidWire)
	}
	leaf.Endpoints = make([]Endpoint, count)
	for i := range int(count) {
		var ep Endpoint
		copy(ep.RelayID[:], data[off:off+20])
		off += 20
		copy(ep.IPv4[:], data[off:off+4])
		off += 4
		copy(ep.IPv6[:], data[off:off+16])
		off += 16
		ep.Port = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		ep.Priority = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		leaf.Endpoints[i] = ep
	}
	return leaf, off, nil
}

// ValidateStructure checks all zone-independent field, ACME, key, and endpoint invariants.
func (r PortalLeafRecord) ValidateStructure() error {
	if r.Version != LeafVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidLeaf, r.Version)
	}
	if r.Flags&^FlagsAllowedMask != 0 {
		return fmt.Errorf("%w: reserved flag bits set", ErrInvalidLeaf)
	}
	if err := validateCanonicalDomain(r.FQDN, 3, maxFQDNLen); err != nil {
		return fmt.Errorf("%w: invalid fqdn: %w", ErrInvalidLeaf, err)
	}
	if r.Seq == 0 {
		return fmt.Errorf("%w: seq must be >= 1", ErrInvalidLeaf)
	}
	if r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > MaxLeafTTL {
		return fmt.Errorf("%w: invalid validity interval", ErrInvalidLeaf)
	}
	if _, err := identity.ParseSecp256k1CompressedPubKey33(r.OwnerPubKey); err != nil {
		return fmt.Errorf("%w: invalid owner_pubkey: %w", ErrInvalidLeaf, err)
	}
	if r.TLSSPKISHA256 == ([32]byte{}) {
		return fmt.Errorf("%w: tls_spki_sha256 must be non-zero", ErrInvalidLeaf)
	}
	if err := r.validateACMEFields(); err != nil {
		return err
	}
	return ValidateEndpoints(r.Endpoints)
}

func (r PortalLeafRecord) validateACMEFields() error {
	if r.ACMECAIssuer == "" {
		if r.ACMEAccountURI != "" {
			return fmt.Errorf("%w: acme_account_uri must be empty when acme_caa_issuer is empty", ErrInvalidLeaf)
		}
		if r.ACMEDNS01Digest != ([32]byte{}) {
			return fmt.Errorf("%w: acme_dns01_digest must be zero when acme_caa_issuer is empty", ErrInvalidLeaf)
		}
		if r.Flags&FlagPersist01Enabled != 0 {
			return fmt.Errorf("%w: PERSIST01_ENABLED requires non-empty acme_caa_issuer", ErrInvalidLeaf)
		}
		return nil
	}
	if err := validateCanonicalDomain(r.ACMECAIssuer, 1, MaxACMEIssuerLen); err != nil {
		return fmt.Errorf("%w: invalid acme_caa_issuer: %w", ErrInvalidLeaf, err)
	}
	if len(r.ACMEAccountURI) == 0 || len(r.ACMEAccountURI) > MaxACMEAccountURILen {
		return fmt.Errorf("%w: invalid acme_account_uri length", ErrInvalidLeaf)
	}
	if !strings.HasPrefix(r.ACMEAccountURI, "https://") || len(r.ACMEAccountURI) == len("https://") {
		return fmt.Errorf("%w: acme_account_uri must be https:// URI", ErrInvalidLeaf)
	}
	for i := range len(r.ACMEAccountURI) {
		b := r.ACMEAccountURI[i]
		if b < 0x21 || b > 0x7e || b == ';' || b == '"' || b == '\\' {
			return fmt.Errorf("%w: acme_account_uri contains disallowed byte 0x%02x", ErrInvalidLeaf, b)
		}
	}
	return nil
}

// ValidateInZone validates structure plus zone-scoped FQDN and class constraints.
func (r PortalLeafRecord) ValidateInZone(zone string) (ParsedFQDN, error) {
	if err := r.ValidateStructure(); err != nil {
		return ParsedFQDN{}, err
	}
	parsed, err := ParseScopedFQDN(r.FQDN, zone)
	if err != nil {
		return ParsedFQDN{}, err
	}
	if parsed.Class == ClassSelfCertifying && r.RecoveryKeyHash != ([32]byte{}) {
		return ParsedFQDN{}, fmt.Errorf("%w: self-certifying leaf must have zero recovery_key_hash", ErrInvalidLeaf)
	}
	return parsed, nil
}

// ValidateEndpoints verifies count (1..8), strict (priority, relay_id) ordering,
// port >= 1 with endpoints[0].port == 443, and utils.IsPublicIP on all addresses.
func ValidateEndpoints(endpoints []Endpoint) error {
	if len(endpoints) == 0 || len(endpoints) > MaxEndpoints {
		return fmt.Errorf("%w: count %d out of range [1, %d]", ErrInvalidEndpoint, len(endpoints), MaxEndpoints)
	}
	if endpoints[0].Port != 443 {
		return fmt.Errorf("%w: endpoints[0].port must be 443, got %d", ErrInvalidEndpoint, endpoints[0].Port)
	}
	for i, ep := range endpoints {
		if ep.Port == 0 {
			return fmt.Errorf("%w: endpoint %d port must be >= 1", ErrInvalidEndpoint, i)
		}
		if err := validateEndpointIPs(ep, i); err != nil {
			return err
		}
		if i > 0 && !endpointStrictlyLess(endpoints[i-1], ep) {
			return fmt.Errorf("%w: endpoints must be strictly sorted by (priority, relay_id)", ErrInvalidEndpoint)
		}
	}
	return nil
}

func validateEndpointIPs(ep Endpoint, idx int) error {
	has4 := ep.IPv4 != ([4]byte{})
	has6 := ep.IPv6 != ([16]byte{})
	if !has4 && !has6 {
		return fmt.Errorf("%w: endpoint %d must have ipv4 or ipv6", ErrInvalidEndpoint, idx)
	}
	if has4 {
		addr4 := netip.AddrFrom4(ep.IPv4)
		if !utils.IsPublicIP(addr4) {
			return fmt.Errorf("%w: endpoint %d ipv4 %s is not public unicast", ErrInvalidEndpoint, idx, addr4)
		}
	}
	if has6 {
		addr6 := netip.AddrFrom16(ep.IPv6)
		if addr6.Is4In6() || !utils.IsPublicIP(addr6) {
			return fmt.Errorf("%w: endpoint %d ipv6 %s is not public unicast", ErrInvalidEndpoint, idx, addr6)
		}
	}
	return nil
}

func endpointStrictlyLess(a, b Endpoint) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return bytes.Compare(a.RelayID[:], b.RelayID[:]) < 0
}

// MarshalCanonical serializes a LeafTx into canonical big-endian wire bytes.
func (tx LeafTx) MarshalCanonical() ([]byte, error) {
	if !isValidTxType(tx.TxType) {
		return nil, fmt.Errorf("%w: unknown tx_type %d", ErrInvalidWire, tx.TxType)
	}
	if (tx.TxType == TxTypeUpdate || tx.TxType == TxTypeColdRecovery) && tx.PoWNonce != 0 {
		return nil, fmt.Errorf("%w: pow_nonce must be 0 for tx_type %d", ErrInvalidWire, tx.TxType)
	}
	leafBytes, err := tx.Leaf.MarshalCanonical()
	if err != nil {
		return nil, err
	}
	extra := 1 + len(leafBytes) + 8 + 64
	if tx.TxType == TxTypeColdRecovery {
		extra += 33 + 64
	}
	buf := make([]byte, 0, extra)
	buf = append(buf, tx.TxType)
	buf = append(buf, leafBytes...)
	buf = binary.BigEndian.AppendUint64(buf, tx.PoWNonce)
	if tx.TxType == TxTypeColdRecovery {
		buf = append(buf, tx.RecoveryPubKey[:]...)
		buf = append(buf, tx.RecoverySig[:]...)
	}
	buf = append(buf, tx.OwnerSig[:]...)
	return buf, nil
}

// UnmarshalLeafTx decodes a canonical LeafTx, rejecting trailing bytes.
func UnmarshalLeafTx(data []byte) (LeafTx, error) {
	tx, consumed, err := decodeLeafTxPrefix(data)
	if err != nil {
		return LeafTx{}, err
	}
	if consumed != len(data) {
		return LeafTx{}, fmt.Errorf("%w: %d trailing bytes", ErrInvalidWire, len(data)-consumed)
	}
	return tx, nil
}

func decodeLeafTxPrefix(data []byte) (LeafTx, int, error) {
	var tx LeafTx
	if len(data) < 1 {
		return LeafTx{}, 0, fmt.Errorf("%w: truncated tx_type", ErrInvalidWire)
	}
	tx.TxType = data[0]
	if !isValidTxType(tx.TxType) {
		return LeafTx{}, 0, fmt.Errorf("%w: unknown tx_type %d", ErrInvalidWire, tx.TxType)
	}
	leaf, consumedLeaf, err := decodeCanonicalLeafPrefix(data[1:])
	if err != nil {
		return LeafTx{}, 0, err
	}
	if err := leaf.ValidateStructure(); err != nil {
		return LeafTx{}, 0, err
	}
	tx.Leaf = leaf
	off := 1 + consumedLeaf
	var ok bool
	if tx.PoWNonce, off, ok = readUint64(data, off); !ok {
		return LeafTx{}, 0, fmt.Errorf("%w: truncated pow_nonce", ErrInvalidWire)
	}
	if (tx.TxType == TxTypeUpdate || tx.TxType == TxTypeColdRecovery) && tx.PoWNonce != 0 {
		return LeafTx{}, 0, fmt.Errorf("%w: pow_nonce must be 0 for tx_type %d", ErrInvalidWire, tx.TxType)
	}
	if tx.TxType == TxTypeColdRecovery {
		if off, ok = readBytes(data, off, tx.RecoveryPubKey[:]); !ok {
			return LeafTx{}, 0, fmt.Errorf("%w: truncated recovery_pubkey", ErrInvalidWire)
		}
		if off, ok = readBytes(data, off, tx.RecoverySig[:]); !ok {
			return LeafTx{}, 0, fmt.Errorf("%w: truncated recovery_sig", ErrInvalidWire)
		}
	}
	if off, ok = readBytes(data, off, tx.OwnerSig[:]); !ok {
		return LeafTx{}, 0, fmt.Errorf("%w: truncated owner_sig", ErrInvalidWire)
	}
	return tx, off, nil
}

// LeafTxOwnerSigningPayload returns the domain-separated payload signed by owner_pubkey.
func LeafTxOwnerSigningPayload(txType uint8, powNonce uint64, canonicalLeaf []byte) []byte {
	out := make([]byte, 0, len(txSignDomain)+1+8+len(canonicalLeaf))
	out = append(out, txSignDomain...)
	out = append(out, txType)
	out = binary.BigEndian.AppendUint64(out, powNonce)
	out = append(out, canonicalLeaf...)
	return out
}

// LeafTxRecoverySigningPayload returns the domain-separated payload signed by recovery_pubkey.
func LeafTxRecoverySigningPayload(canonicalLeaf []byte) []byte {
	out := make([]byte, 0, len(recoverySignDomain)+len(canonicalLeaf))
	out = append(out, recoverySignDomain...)
	out = append(out, canonicalLeaf...)
	return out
}

// SignLeafTxOwner signs tx with ownerKey in strict BIP-62 low-S form and sets OwnerSig.
func (tx *LeafTx) SignOwner(ownerKey *secp256k1.PrivateKey) error {
	if ownerKey == nil {
		return errOwnerKeyRequired
	}
	copy(tx.Leaf.OwnerPubKey[:], ownerKey.PubKey().SerializeCompressed())
	canonicalLeaf, err := tx.Leaf.MarshalCanonical()
	if err != nil {
		return err
	}
	sig, err := identity.SignSHA256Secp256k1LowSRaw64(
		LeafTxOwnerSigningPayload(tx.TxType, tx.PoWNonce, canonicalLeaf),
		ownerKey,
	)
	if err != nil {
		return err
	}
	copy(tx.OwnerSig[:], sig)
	return nil
}

// SignRecovery sets RecoveryPubKey and signs Leaf with coldKey in strict BIP-62 low-S form.
func (tx *LeafTx) SignRecovery(coldKey *secp256k1.PrivateKey) error {
	if coldKey == nil {
		return errRecoveryKeyRequired
	}
	copy(tx.RecoveryPubKey[:], coldKey.PubKey().SerializeCompressed())
	canonicalLeaf, err := tx.Leaf.MarshalCanonical()
	if err != nil {
		return err
	}
	sig, err := identity.SignSHA256Secp256k1LowSRaw64(
		LeafTxRecoverySigningPayload(canonicalLeaf),
		coldKey,
	)
	if err != nil {
		return err
	}
	copy(tx.RecoverySig[:], sig)
	return nil
}

// CanonicalBatchBytes encodes ordered LeafTx entries with a uint32 count prefix.
func CanonicalBatchBytes(txs []LeafTx) ([]byte, error) {
	out := make([]byte, 0, 4+len(txs)*128)
	out = binary.BigEndian.AppendUint32(out, uint32(len(txs)))
	for _, tx := range txs {
		raw, err := tx.MarshalCanonical()
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	return out, nil
}

// UnmarshalCanonicalBatch decodes canonical batch transactions, rejecting trailing bytes.
func UnmarshalCanonicalBatch(data []byte) ([]LeafTx, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: truncated batch count", ErrInvalidWire)
	}
	count := binary.BigEndian.Uint32(data[:4])
	if count > MaxBatchSize {
		return nil, fmt.Errorf("%w: batch size %d exceeds %d", ErrInvalidWire, count, MaxBatchSize)
	}
	off := 4
	txs := make([]LeafTx, count)
	for i := range int(count) {
		tx, consumed, err := decodeLeafTxPrefix(data[off:])
		if err != nil {
			return nil, fmt.Errorf("tx[%d]: %w", i, err)
		}
		txs[i] = tx
		off += consumed
	}
	if off != len(data) {
		return nil, fmt.Errorf("%w: %d trailing bytes in batch", ErrInvalidWire, len(data)-off)
	}
	return txs, nil
}

func isValidTxType(txType uint8) bool {
	return txType >= TxTypeCreate && txType <= TxTypeReclaim
}

// OccupiedLeafDigest computes SHA256(CanonicalLeafBytes) for helper inspection.
func (r PortalLeafRecord) CanonicalSHA256() ([32]byte, error) {
	raw, err := r.MarshalCanonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func appendUint8String(dst []byte, s string) []byte {
	dst = append(dst, uint8(len(s)))
	return append(dst, s...)
}

func readUint8(src []byte, off int) (uint8, int, bool) {
	if off >= len(src) {
		return 0, off, false
	}
	return src[off], off + 1, true
}

func readUint16(src []byte, off int) (uint16, int, bool) {
	if off+2 > len(src) {
		return 0, off, false
	}
	return binary.BigEndian.Uint16(src[off : off+2]), off + 2, true
}

func readUint64(src []byte, off int) (uint64, int, bool) {
	if off+8 > len(src) {
		return 0, off, false
	}
	return binary.BigEndian.Uint64(src[off : off+8]), off + 8, true
}

func readUint8String(src []byte, off int) (string, int, bool) {
	n, nextOff, ok := readUint8(src, off)
	if !ok || nextOff+int(n) > len(src) {
		return "", off, false
	}
	return string(src[nextOff : nextOff+int(n)]), nextOff + int(n), true
}

func readBytes(src []byte, off int, dst []byte) (int, bool) {
	if off+len(dst) > len(src) {
		return off, false
	}
	copy(dst, src[off:off+len(dst)])
	return off + len(dst), true
}
