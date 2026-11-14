package pgns

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

const resolveBundleVersion uint8 = 1

// MarshalBinary serializes BatchTransitionProof into canonical big-endian wire bytes.
func (b BatchTransitionProof) MarshalBinary() ([]byte, error) {
	if err := ValidateZone(b.Zone); err != nil {
		return nil, err
	}
	if len(b.TxEntries) > MaxBatchSize || len(b.PrevLeaves) != len(b.TxEntries) {
		return nil, fmt.Errorf("%w: invalid batch length (%d txs, %d prev leaves)", ErrInvalidBatch, len(b.TxEntries), len(b.PrevLeaves))
	}
	batchBytes, err := CanonicalBatchBytes(b.TxEntries)
	if err != nil {
		return nil, err
	}
	mpBytes, err := b.PreStateMP.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(b.ConsistencyProof) > 65535 || len(b.AppendRecordProof) > 65535 {
		return nil, fmt.Errorf("%w: proof hash list too large", ErrInvalidWire)
	}

	out := make([]byte, 0, 256+len(batchBytes)+len(mpBytes))
	out = appendUint8String(out, b.Zone)
	out = binary.BigEndian.AppendUint64(out, b.Epoch)
	out = binary.BigEndian.AppendUint64(out, b.Timestamp)
	out = append(out, b.PrevLogRoot[:]...)
	out = append(out, b.NewLogRoot[:]...)
	out = append(out, b.PrevSMTRoot[:]...)
	out = append(out, b.NewSMTRoot[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(batchBytes)))
	out = append(out, batchBytes...)
	for _, prev := range b.PrevLeaves {
		if len(prev) == 0 {
			out = append(out, 0)
			continue
		}
		if len(prev) > 65535 {
			return nil, fmt.Errorf("%w: prev leaf too large", ErrInvalidWire)
		}
		out = append(out, 1)
		out = binary.BigEndian.AppendUint16(out, uint16(len(prev)))
		out = append(out, prev...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(mpBytes)))
	out = append(out, mpBytes...)
	out = appendTlogHashes(out, b.ConsistencyProof)
	out = appendTlogHashes(out, b.AppendRecordProof)
	return out, nil
}

// UnmarshalBatchTransitionProof decodes a canonical BatchTransitionProof, rejecting trailing bytes.
func UnmarshalBatchTransitionProof(data []byte) (BatchTransitionProof, error) {
	var b BatchTransitionProof
	off := 0
	var ok bool
	if b.Zone, off, ok = readUint8String(data, off); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated zone", ErrInvalidWire)
	}
	if err := ValidateZone(b.Zone); err != nil {
		return BatchTransitionProof{}, err
	}
	if b.Epoch, off, ok = readUint64(data, off); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated epoch", ErrInvalidWire)
	}
	if b.Timestamp, off, ok = readUint64(data, off); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated timestamp", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, b.PrevLogRoot[:]); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated prev_log_root", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, b.NewLogRoot[:]); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated new_log_root", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, b.PrevSMTRoot[:]); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated prev_smt_root", ErrInvalidWire)
	}
	if off, ok = readBytes(data, off, b.NewSMTRoot[:]); !ok {
		return BatchTransitionProof{}, fmt.Errorf("%w: truncated new_smt_root", ErrInvalidWire)
	}
	var batchBytes []byte
	var err error
	if batchBytes, off, err = readUint32Bytes(data, off); err != nil {
		return BatchTransitionProof{}, err
	}
	if b.TxEntries, err = UnmarshalCanonicalBatch(batchBytes); err != nil {
		return BatchTransitionProof{}, err
	}
	b.PrevLeaves = make([][]byte, len(b.TxEntries))
	for i := range b.TxEntries {
		present, nextOff, flagOK := readUint8(data, off)
		if !flagOK {
			return BatchTransitionProof{}, fmt.Errorf("%w: truncated prev leaf flag", ErrInvalidWire)
		}
		off = nextOff
		switch present {
		case 0:
		case 1:
			prev, nextOff2, leafErr := readUint16Bytes(data, off)
			if leafErr != nil {
				return BatchTransitionProof{}, leafErr
			}
			b.PrevLeaves[i] = prev
			off = nextOff2
		default:
			return BatchTransitionProof{}, fmt.Errorf("%w: invalid prev leaf flag %d", ErrInvalidWire, present)
		}
	}
	var mpBytes []byte
	if mpBytes, off, err = readUint32Bytes(data, off); err != nil {
		return BatchTransitionProof{}, err
	}
	if b.PreStateMP, err = UnmarshalBatchMultiproof(mpBytes); err != nil {
		return BatchTransitionProof{}, err
	}
	var consHashes, recHashes []tlog.Hash
	if consHashes, off, err = readTlogHashes(data, off); err != nil {
		return BatchTransitionProof{}, err
	}
	if recHashes, off, err = readTlogHashes(data, off); err != nil {
		return BatchTransitionProof{}, err
	}
	b.ConsistencyProof = tlog.TreeProof(consHashes)
	b.AppendRecordProof = tlog.RecordProof(recHashes)
	if off != len(data) {
		return BatchTransitionProof{}, fmt.Errorf("%w: %d trailing bytes in batch proof", ErrInvalidWire, len(data)-off)
	}
	return b, nil
}

// ResolveBundle is the CDN-cacheable self-verifying binary payload served by /v1/resolve/<fqdn>.
type ResolveBundle struct {
	Leaf             []byte
	InclusionProof   []byte
	SignedCheckpoint []byte
}

// MarshalBinary encodes ResolveBundle with canonical length prefixes.
func (r ResolveBundle) MarshalBinary() ([]byte, error) {
	if len(r.Leaf) > 65535 || len(r.InclusionProof) > 65535 || len(r.SignedCheckpoint) == 0 {
		return nil, fmt.Errorf("%w: invalid resolve bundle lengths", ErrInvalidWire)
	}
	out := make([]byte, 0, 1+2+len(r.Leaf)+2+len(r.InclusionProof)+4+len(r.SignedCheckpoint))
	out = append(out, resolveBundleVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Leaf)))
	out = append(out, r.Leaf...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.InclusionProof)))
	out = append(out, r.InclusionProof...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(r.SignedCheckpoint)))
	out = append(out, r.SignedCheckpoint...)
	return out, nil
}

// UnmarshalResolveBundle decodes ResolveBundle and rejects trailing bytes.
func UnmarshalResolveBundle(data []byte) (ResolveBundle, error) {
	if len(data) < 1 || data[0] != resolveBundleVersion {
		return ResolveBundle{}, fmt.Errorf("%w: unsupported resolve bundle version", ErrInvalidWire)
	}
	off := 1
	leaf, off, err := readUint16Bytes(data, off)
	if err != nil {
		return ResolveBundle{}, err
	}
	proof, off, err := readUint16Bytes(data, off)
	if err != nil {
		return ResolveBundle{}, err
	}
	cp, off, err := readUint32Bytes(data, off)
	if err != nil {
		return ResolveBundle{}, err
	}
	if off != len(data) {
		return ResolveBundle{}, fmt.Errorf("%w: %d trailing bytes in resolve bundle", ErrInvalidWire, len(data)-off)
	}
	return ResolveBundle{
		Leaf:             leaf,
		InclusionProof:   proof,
		SignedCheckpoint: cp,
	}, nil
}

// VerifyResolveBundle decodes and cryptographically verifies a CDN-served ResolveBundle
// for expectedFQDN inside zone against ws at time now.
func VerifyResolveBundle(raw []byte, expectedFQDN, zone string, ws WitnessSet, now uint64) (PortalLeafRecord, Checkpoint, error) {
	bundle, err := UnmarshalResolveBundle(raw)
	if err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	leaf, cp, err := VerifyRegistrationProof(zone, ws, bundle.Leaf, bundle.InclusionProof, bundle.SignedCheckpoint, now)
	if err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	if leaf.FQDN != expectedFQDN {
		return PortalLeafRecord{}, Checkpoint{}, fmt.Errorf("%w: leaf fqdn %q != requested %q", ErrInvalidLeaf, leaf.FQDN, expectedFQDN)
	}
	return leaf, cp, nil
}

func appendTlogHashes(dst []byte, hashes []tlog.Hash) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(hashes)))
	for _, h := range hashes {
		dst = append(dst, h[:]...)
	}
	return dst
}

func readTlogHashes(src []byte, off int) ([]tlog.Hash, int, error) {
	count, nextOff, ok := readUint16(src, off)
	if !ok {
		return nil, off, fmt.Errorf("%w: truncated tlog hash count", ErrInvalidWire)
	}
	off = nextOff
	if len(src)-off < int(count)*tlog.HashSize {
		return nil, off, fmt.Errorf("%w: truncated tlog hashes", ErrInvalidWire)
	}
	out := make([]tlog.Hash, count)
	for i := range int(count) {
		copy(out[i][:], src[off:off+tlog.HashSize])
		off += tlog.HashSize
	}
	return out, off, nil
}

func readUint16Bytes(src []byte, off int) ([]byte, int, error) {
	n, nextOff, ok := readUint16(src, off)
	if !ok || nextOff+int(n) > len(src) {
		return nil, off, fmt.Errorf("%w: truncated uint16 slice", ErrInvalidWire)
	}
	out := make([]byte, n)
	copy(out, src[nextOff:nextOff+int(n)])
	return out, nextOff + int(n), nil
}

func readUint32Bytes(src []byte, off int) ([]byte, int, error) {
	if off+4 > len(src) {
		return nil, off, fmt.Errorf("%w: truncated uint32 length", ErrInvalidWire)
	}
	n := binary.BigEndian.Uint32(src[off : off+4])
	off += 4
	if n > uint32(len(src)-off) {
		return nil, off, fmt.Errorf("%w: truncated uint32 slice", ErrInvalidWire)
	}
	out := make([]byte, n)
	copy(out, src[off:off+int(n)])
	return out, off + int(n), nil
}
