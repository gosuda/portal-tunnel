package pgns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	CheckpointOriginPrefix = "portal-pgns-v1/"
	checkpointSMTTag       = "smt-v1"
	epochRecordDomain      = "portal-pgns-epoch-v1\x00"
	cosigHeaderV1          = "cosignature/v1"
	cosigSignaturePrefix   = "— " // U+2014 + space per c2sp.org/signed-note

	WitnessStateBytes      = 88
	WitnessClockSkew       = uint64(30)
	RelayCheckpointMaxAge  = uint64(600)
	RelayCheckpointMaxLead = uint64(60)
)

var (
	// ErrInvalidCheckpoint marks malformed or threshold-insufficient signed checkpoints.
	ErrInvalidCheckpoint = errors.New("pgns: invalid signed checkpoint")
	// ErrStaleCheckpoint marks expired or future-skewed checkpoint timestamps.
	ErrStaleCheckpoint = errors.New("pgns: stale checkpoint timestamp")
	// ErrInvalidBatch marks an invalid epoch transition batch or log proof.
	ErrInvalidBatch = errors.New("pgns: invalid batch transition")
)

// EpochRecordHash computes the transparency log leaf digest for epoch:
// SHA256(0x00 || "portal-pgns-epoch-v1\x00" || uint64_be(epoch) || uint64_be(timestamp) || smt_root_32B || sha256(batchBytes)).
func EpochRecordHash(epoch, timestamp uint64, smtRoot [32]byte, batchBytes []byte) [32]byte {
	batchDigest := sha256.Sum256(batchBytes)
	h := sha256.New()
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write([]byte(epochRecordDomain))
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], epoch)
	_, _ = h.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], timestamp)
	_, _ = h.Write(u64[:])
	_, _ = h.Write(smtRoot[:])
	_, _ = h.Write(batchDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeAppendLogRoot appends recordHash to an RFC 6962 / C2SP tlog-tiles tree
// of oldSize using the provided HashReader (nil allowed when oldSize == 0).
func ComputeAppendLogRoot(oldSize uint64, recordHash [32]byte, hr tlog.HashReader) ([32]byte, []tlog.Hash, error) {
	if oldSize > math.MaxInt64-1 {
		return [32]byte{}, nil, fmt.Errorf("%w: log size overflow", ErrInvalidBatch)
	}
	n := int64(oldSize)
	newHashes, err := tlog.StoredHashesForRecordHash(n, tlog.Hash(recordHash), hr)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("%w: store hashes: %w", ErrInvalidBatch, err)
	}
	var rootReader tlog.HashReaderFunc = func(indexes []int64) ([]tlog.Hash, error) {
		minStored := tlog.StoredHashCount(n)
		var fetch []int64
		for _, idx := range indexes {
			if idx < minStored {
				fetch = append(fetch, idx)
			}
		}
		fetchedMap := make(map[int64]tlog.Hash, len(fetch))
		if len(fetch) > 0 {
			got, err := hr.ReadHashes(fetch)
			if err != nil {
				return nil, err
			}
			for i, idx := range fetch {
				fetchedMap[idx] = got[i]
			}
		}
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < minStored {
				out[i] = fetchedMap[idx]
			} else {
				rel := idx - minStored
				if rel < 0 || int(rel) >= len(newHashes) {
					return nil, fmt.Errorf("missing new stored hash %d", idx)
				}
				out[i] = newHashes[rel]
			}
		}
		return out, nil
	}
	root, err := tlog.TreeHash(n+1, rootReader)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("%w: tree hash: %w", ErrInvalidBatch, err)
	}
	return [32]byte(root), newHashes, nil
}

// Checkpoint represents the unsigned 4-line C2SP PGNS checkpoint body.
type Checkpoint struct {
	Origin    string
	LogSize   uint64
	LogRoot   [32]byte
	Epoch     uint64
	Timestamp uint64
	SMTRoot   [32]byte
}

// FormatBody formats the canonical 4-line C2SP checkpoint body ending with newline.
func (c Checkpoint) FormatBody() []byte {
	var sb strings.Builder
	sb.WriteString(c.Origin)
	sb.WriteByte('\n')
	sb.WriteString(strconv.FormatUint(c.LogSize, 10))
	sb.WriteByte('\n')
	sb.WriteString(base64.StdEncoding.EncodeToString(c.LogRoot[:]))
	sb.WriteByte('\n')
	sb.WriteString(checkpointSMTTag)
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(c.Epoch, 10))
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(c.Timestamp, 10))
	sb.WriteByte(' ')
	sb.WriteString(base64.StdEncoding.EncodeToString(c.SMTRoot[:]))
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// ParseCheckpointBody parses the exact 4-line PGNS C2SP checkpoint body for zone.
func ParseCheckpointBody(body []byte, zone string) (Checkpoint, error) {
	if !strings.HasSuffix(string(body), "\n") {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint body must end with newline", ErrInvalidCheckpoint)
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) != 4 {
		return Checkpoint{}, fmt.Errorf("%w: expected 4 body lines, got %d", ErrInvalidCheckpoint, len(lines))
	}
	wantOrigin := CheckpointOriginPrefix + zone
	if lines[0] != wantOrigin {
		return Checkpoint{}, fmt.Errorf("%w: origin %q != %q", ErrInvalidCheckpoint, lines[0], wantOrigin)
	}
	logSize, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: invalid log_size: %w", ErrInvalidCheckpoint, err)
	}
	logRootSlice, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(logRootSlice) != 32 {
		return Checkpoint{}, fmt.Errorf("%w: invalid log_root", ErrInvalidCheckpoint)
	}
	fields := strings.Split(lines[3], " ")
	if len(fields) != 4 || fields[0] != checkpointSMTTag {
		return Checkpoint{}, fmt.Errorf("%w: invalid smt extension line", ErrInvalidCheckpoint)
	}
	epoch, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: invalid epoch: %w", ErrInvalidCheckpoint, err)
	}
	ts, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: invalid timestamp: %w", ErrInvalidCheckpoint, err)
	}
	smtRootSlice, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil || len(smtRootSlice) != 32 {
		return Checkpoint{}, fmt.Errorf("%w: invalid smt_root", ErrInvalidCheckpoint)
	}
	if epoch == math.MaxUint64 || logSize != epoch+1 {
		return Checkpoint{}, fmt.Errorf("%w: log_size %d != epoch+1 (%d)", ErrInvalidCheckpoint, logSize, epoch+1)
	}
	var cp Checkpoint
	cp.Origin = lines[0]
	cp.LogSize = logSize
	copy(cp.LogRoot[:], logRootSlice)
	cp.Epoch = epoch
	cp.Timestamp = ts
	copy(cp.SMTRoot[:], smtRootSlice)
	return cp, nil
}

// WitnessKey identifies one trusted PGNS witness Ed25519 cosigner.
type WitnessKey struct {
	Name      string
	PublicKey ed25519.PublicKey
}

// KeyID computes the 4-byte C2SP cosignature/v1 key ID.
func (w WitnessKey) KeyID() [4]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(w.Name))
	_, _ = h.Write([]byte{'\n', 0x04})
	_, _ = h.Write(w.PublicKey)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

// WitnessSet defines the k-of-m witness quorum accepted by relays, SDK clients, and DNS signers.
type WitnessSet struct {
	Threshold int
	Witnesses []WitnessKey
}

// WitnessCosignature holds one verified C2SP cosignature/v1 line.
type WitnessCosignature struct {
	Name      string
	Timestamp uint64
	Signature []byte // 76-byte wire payload: keyID[4] || ts[8] || ed25519[64]
}

// CosignCheckpoint creates one C2SP cosignature/v1 note signature line.
func CosignCheckpoint(body []byte, key WitnessKey, priv ed25519.PrivateKey, cosigTimestamp uint64) (WitnessCosignature, error) {
	if len(priv) != ed25519.PrivateKeySize || len(key.PublicKey) != ed25519.PublicKeySize || key.Name == "" {
		return WitnessCosignature{}, fmt.Errorf("%w: invalid witness signing key", ErrInvalidCheckpoint)
	}
	msg := cosigSignedMessage(body, cosigTimestamp)
	sig := ed25519.Sign(priv, msg)
	keyID := key.KeyID()
	wire := make([]byte, 4+8+ed25519.SignatureSize)
	copy(wire[:4], keyID[:])
	binary.BigEndian.PutUint64(wire[4:12], cosigTimestamp)
	copy(wire[12:], sig)
	return WitnessCosignature{
		Name:      key.Name,
		Timestamp: cosigTimestamp,
		Signature: wire,
	}, nil
}

// FormatLine formats the C2SP note signature line (without trailing newline).
func (c WitnessCosignature) FormatLine() string {
	return cosigSignaturePrefix + c.Name + " " + base64.StdEncoding.EncodeToString(c.Signature)
}

// FormatSignedCheckpoint serializes a C2SP signed note containing body and cosignatures.
func FormatSignedCheckpoint(body []byte, cosigs []WitnessCosignature) []byte {
	var sb strings.Builder
	sb.Write(body)
	sb.WriteByte('\n')
	for _, cosig := range cosigs {
		sb.WriteString(cosig.FormatLine())
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// ParseAndVerifySignedCheckpoint verifies a C2SP signed note against zone and ws quorum.
func ParseAndVerifySignedCheckpoint(raw []byte, zone string, ws WitnessSet) (Checkpoint, []WitnessCosignature, error) {
	if ws.Threshold <= 0 || ws.Threshold > len(ws.Witnesses) {
		return Checkpoint{}, nil, fmt.Errorf("%w: invalid witness threshold %d/%d", ErrInvalidCheckpoint, ws.Threshold, len(ws.Witnesses))
	}
	sepIdx := bytes.Index(raw, []byte("\n\n"))
	if sepIdx < 0 {
		return Checkpoint{}, nil, fmt.Errorf("%w: missing note separator", ErrInvalidCheckpoint)
	}
	body := raw[:sepIdx+1]
	cp, err := ParseCheckpointBody(body, zone)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	sigSection := strings.TrimSuffix(string(raw[sepIdx+2:]), "\n")
	if sigSection == "" {
		return Checkpoint{}, nil, fmt.Errorf("%w: missing cosignatures", ErrInvalidCheckpoint)
	}
	byName := make(map[string]WitnessKey, len(ws.Witnesses))
	for _, w := range ws.Witnesses {
		byName[w.Name] = w
	}
	seen := make(map[string]struct{}, len(ws.Witnesses))
	var verified []WitnessCosignature
	for _, line := range strings.Split(sigSection, "\n") {
		cosig, ok := verifyOneCosigLine(line, body, byName)
		if !ok {
			continue
		}
		if _, dup := seen[cosig.Name]; dup {
			continue
		}
		seen[cosig.Name] = struct{}{}
		verified = append(verified, cosig)
	}
	if len(verified) < ws.Threshold {
		return Checkpoint{}, nil, fmt.Errorf("%w: verified %d witnesses, need %d", ErrInvalidCheckpoint, len(verified), ws.Threshold)
	}
	return cp, verified, nil
}

func verifyOneCosigLine(line string, body []byte, byName map[string]WitnessKey) (WitnessCosignature, bool) {
	rest, ok := strings.CutPrefix(line, cosigSignaturePrefix)
	if !ok {
		return WitnessCosignature{}, false
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok {
		return WitnessCosignature{}, false
	}
	w, known := byName[name]
	if !known {
		return WitnessCosignature{}, false
	}
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(payload) != 4+8+ed25519.SignatureSize {
		return WitnessCosignature{}, false
	}
	expectedID := w.KeyID()
	if !bytes.Equal(payload[:4], expectedID[:]) {
		return WitnessCosignature{}, false
	}
	ts := binary.BigEndian.Uint64(payload[4:12])
	msg := cosigSignedMessage(body, ts)
	if !ed25519.Verify(w.PublicKey, msg, payload[12:]) {
		return WitnessCosignature{}, false
	}
	return WitnessCosignature{Name: name, Timestamp: ts, Signature: payload}, true
}

func cosigSignedMessage(body []byte, ts uint64) []byte {
	header := cosigHeaderV1 + "\ntime " + strconv.FormatUint(ts, 10) + "\n"
	out := make([]byte, len(header)+len(body))
	copy(out, header)
	copy(out[len(header):], body)
	return out
}

// CheckCheckpointFreshness validates -maxLead <= now - cpTimestamp <= maxAge (overflow-safe).
func CheckCheckpointFreshness(cpTimestamp, now, maxLead, maxAge uint64) error {
	if cpTimestamp > now && cpTimestamp-now > maxLead {
		return fmt.Errorf("%w: checkpoint timestamp %d ahead of %d by more than %ds", ErrStaleCheckpoint, cpTimestamp, now, maxLead)
	}
	if now > cpTimestamp && now-cpTimestamp > maxAge {
		return fmt.Errorf("%w: checkpoint timestamp %d older than %d by more than %ds", ErrStaleCheckpoint, cpTimestamp, now, maxAge)
	}
	return nil
}

// WitnessState stores the exact 88-byte persistent witness checkpoint summary.
type WitnessState struct {
	Epoch     uint64
	Timestamp uint64
	LogSize   uint64
	LogRoot   [32]byte
	SMTRoot   [32]byte
}

// MarshalBinary encodes WitnessState into exact 88 big-endian bytes.
func (s WitnessState) MarshalBinary() [WitnessStateBytes]byte {
	var out [WitnessStateBytes]byte
	binary.BigEndian.PutUint64(out[0:8], s.Epoch)
	binary.BigEndian.PutUint64(out[8:16], s.Timestamp)
	binary.BigEndian.PutUint64(out[16:24], s.LogSize)
	copy(out[24:56], s.LogRoot[:])
	copy(out[56:88], s.SMTRoot[:])
	return out
}

// UnmarshalWitnessState decodes exact 88-byte witness persistent state.
func UnmarshalWitnessState(data []byte) (WitnessState, error) {
	if len(data) != WitnessStateBytes {
		return WitnessState{}, fmt.Errorf("%w: witness state length %d != %d", ErrInvalidWire, len(data), WitnessStateBytes)
	}
	var s WitnessState
	s.Epoch = binary.BigEndian.Uint64(data[0:8])
	s.Timestamp = binary.BigEndian.Uint64(data[8:16])
	s.LogSize = binary.BigEndian.Uint64(data[16:24])
	copy(s.LogRoot[:], data[24:56])
	copy(s.SMTRoot[:], data[56:88])
	return s, nil
}

// VerifyRegistrationProof performs zero-RPC offline verification of a PGNS leaf,
// its SMTInclusionProof, and witness-quorum SignedCheckpoint at unix time now.
func VerifyRegistrationProof(zone string, ws WitnessSet, rawLeaf, rawProof, rawCheckpoint []byte, now uint64) (PortalLeafRecord, Checkpoint, error) {
	cp, _, err := ParseAndVerifySignedCheckpoint(rawCheckpoint, zone, ws)
	if err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	if err := CheckCheckpointFreshness(cp.Timestamp, now, RelayCheckpointMaxLead, RelayCheckpointMaxAge); err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	leaf, err := UnmarshalCanonicalLeaf(rawLeaf)
	if err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	if _, err := leaf.ValidateInZone(zone); err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	if now >= leaf.ExpiresAt {
		return PortalLeafRecord{}, Checkpoint{}, fmt.Errorf("%w: leaf expired at %d (now %d)", ErrStaleCheckpoint, leaf.ExpiresAt, now)
	}
	proof, err := UnmarshalSMTProof(rawProof)
	if err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	if err := VerifyInclusionProof(SMTKey(leaf.FQDN), rawLeaf, proof, cp.SMTRoot); err != nil {
		return PortalLeafRecord{}, Checkpoint{}, err
	}
	return leaf, cp, nil
}

// BatchTransitionProof is the complete stateless verification bundle submitted by
// pgns-sequencer to pgns-witness (and archived publicly alongside C2SP tiles).
type BatchTransitionProof struct {
	Zone              string
	Epoch             uint64
	Timestamp         uint64
	PrevLogRoot       [32]byte
	NewLogRoot        [32]byte
	PrevSMTRoot       [32]byte
	NewSMTRoot        [32]byte
	TxEntries         []LeafTx
	PrevLeaves        [][]byte // len == len(TxEntries); nil/empty slice means absent prior leaf
	PreStateMP        BatchMultiproof
	ConsistencyProof  tlog.TreeProof // proves PrevLogRoot (size Epoch) -> NewLogRoot (size Epoch+1)
}

// VerifyBatchTransition runs the 5-step stateless witness verification against prevState
// (nil at genesis epoch 0) at witness wall-clock time witnessNow.
func VerifyBatchTransition(prev *WitnessState, b BatchTransitionProof, witnessNow uint64) (WitnessState, error) {
	if err := ValidateZone(b.Zone); err != nil {
		return WitnessState{}, err
	}
	if err := CheckCheckpointFreshness(b.Timestamp, witnessNow, WitnessClockSkew, WitnessClockSkew); err != nil {
		return WitnessState{}, err
	}
	prevLogSize, prevLogRoot, prevSMTRoot, err := verifyBatchHeaderState(prev, b)
	if err != nil {
		return WitnessState{}, err
	}
	if len(b.TxEntries) > MaxBatchSize || len(b.PrevLeaves) != len(b.TxEntries) {
		return WitnessState{}, fmt.Errorf("%w: batch size mismatch (%d txs, %d prev leaves)", ErrInvalidBatch, len(b.TxEntries), len(b.PrevLeaves))
	}
	if err := verifyBatchUpdates(b, prevSMTRoot); err != nil {
		return WitnessState{}, err
	}
	if err := verifyBatchLogAppend(b, prevLogSize, prevLogRoot); err != nil {
		return WitnessState{}, err
	}
	return WitnessState{
		Epoch:     b.Epoch,
		Timestamp: b.Timestamp,
		LogSize:   b.Epoch + 1,
		LogRoot:   b.NewLogRoot,
		SMTRoot:   b.NewSMTRoot,
	}, nil
}

func verifyBatchHeaderState(prev *WitnessState, b BatchTransitionProof) (uint64, [32]byte, [32]byte, error) {
	if prev == nil {
		if b.Epoch != 0 {
			return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: genesis must have epoch 0", ErrInvalidBatch)
		}
		if b.PrevSMTRoot != EmptySubtree[0] || b.PrevLogRoot != ([32]byte{}) {
			return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: non-zero genesis pre-state roots", ErrInvalidBatch)
		}
		return 0, [32]byte{}, EmptySubtree[0], nil
	}
	if prev.Epoch == math.MaxUint64 || b.Epoch != prev.Epoch+1 {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: epoch %d != prev.epoch+1 (%d)", ErrInvalidBatch, b.Epoch, prev.Epoch+1)
	}
	if prev.LogSize != prev.Epoch+1 {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: corrupted prev log size", ErrInvalidBatch)
	}
	if b.Timestamp < prev.Timestamp {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: epoch timestamp %d < prev %d", ErrInvalidBatch, b.Timestamp, prev.Timestamp)
	}
	if b.PrevLogRoot != prev.LogRoot || b.PrevSMTRoot != prev.SMTRoot {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("%w: pre-state root mismatch vs witness state", ErrInvalidBatch)
	}
	return prev.LogSize, prev.LogRoot, prev.SMTRoot, nil
}

func verifyBatchUpdates(b BatchTransitionProof, prevSMTRoot [32]byte) error {
	if len(b.TxEntries) == 0 {
		if b.NewSMTRoot != prevSMTRoot {
			return fmt.Errorf("%w: 0-tx epoch changed smt_root", ErrInvalidBatch)
		}
		if b.PreStateMP.BitCount != 0 || len(b.PreStateMP.Siblings) != 0 {
			return fmt.Errorf("%w: 0-tx epoch must have empty multiproof", ErrInvalidBatch)
		}
		return nil
	}
	updates := make([]BatchUpdate, len(b.TxEntries))
	for i, tx := range b.TxEntries {
		key := SMTKey(tx.Leaf.FQDN)
		if i > 0 && bytes.Compare(updates[i-1].Key[:], key[:]) >= 0 {
			return fmt.Errorf("%w: tx leaf keys must be strictly ascending", ErrInvalidBatch)
		}
		var prevPtr *PortalLeafRecord
		oldHash := EmptySubtree[smtDepth]
		if len(b.PrevLeaves[i]) > 0 {
			prevLeaf, err := UnmarshalCanonicalLeaf(b.PrevLeaves[i])
			if err != nil {
				return fmt.Errorf("%w: tx[%d] prev leaf: %w", ErrInvalidBatch, i, err)
			}
			if prevLeaf.FQDN != tx.Leaf.FQDN {
				return fmt.Errorf("%w: tx[%d] prev leaf fqdn mismatch", ErrInvalidBatch, i)
			}
			prevPtr = &prevLeaf
			oldHash = OccupiedLeafHash(key, b.PrevLeaves[i])
		}
		if err := ValidateTransition(prevPtr, tx, b.Timestamp, b.Zone); err != nil {
			return fmt.Errorf("tx[%d]: %w", i, err)
		}
		newCanonical, err := tx.Leaf.MarshalCanonical()
		if err != nil {
			return fmt.Errorf("tx[%d]: %w", i, err)
		}
		updates[i] = BatchUpdate{
			Key:     key,
			OldHash: oldHash,
			NewHash: OccupiedLeafHash(key, newCanonical),
		}
	}
	computedPostRoot, err := VerifyAndApplyMultiproof(updates, b.PreStateMP, prevSMTRoot)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBatch, err)
	}
	if computedPostRoot != b.NewSMTRoot {
		return fmt.Errorf("%w: post-state smt_root mismatch", ErrInvalidBatch)
	}
	return nil
}

func verifyBatchLogAppend(b BatchTransitionProof, prevLogSize uint64, prevLogRoot [32]byte) error {
	batchBytes, err := CanonicalBatchBytes(b.TxEntries)
	if err != nil {
		return fmt.Errorf("%w: encode batch: %w", ErrInvalidBatch, err)
	}
	recHash := EpochRecordHash(b.Epoch, b.Timestamp, b.NewSMTRoot, batchBytes)
	if prevLogSize == 0 {
		expectedRoot, _, err := ComputeAppendLogRoot(0, recHash, nil)
		if err != nil {
			return err
		}
		if b.NewLogRoot != expectedRoot || len(b.ConsistencyProof) != 0 || len(b.AppendRecordProof) != 0 {
			return fmt.Errorf("%w: genesis log root mismatch", ErrInvalidBatch)
		}
		return nil
	}
	if err := tlog.CheckTree(b.ConsistencyProof, int64(prevLogSize), tlog.Hash(prevLogRoot), int64(b.Epoch+1), tlog.Hash(b.NewLogRoot)); err != nil {
		return fmt.Errorf("%w: c2sp log consistency: %w", ErrInvalidBatch, err)
	}
	if err := tlog.CheckRecord(b.AppendRecordProof, int64(b.Epoch+1), tlog.Hash(b.NewLogRoot), int64(b.Epoch), tlog.Hash(recHash)); err != nil {
		return fmt.Errorf("%w: epoch record inclusion: %w", ErrInvalidBatch, err)
	}
	return nil
}
