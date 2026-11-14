package pgns

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

const (
	smtKeyDomain = "portal-smt-key-v1\x00"
	smtDepth     = 256
)

var (
	// ErrInvalidSMTProof marks a malformed, non-canonical, or mismatched Merkle proof.
	ErrInvalidSMTProof = errors.New("pgns: invalid smt proof")
)

// EmptySubtree stores the precomputed zero-tree root hashes from depth 0 (root)
// down to depth 256 (empty leaf sentinel 0x00*32).
var EmptySubtree [smtDepth + 1][32]byte

func init() {
	for d := smtDepth - 1; d >= 0; d-- {
		EmptySubtree[d] = InternalNodeHash(EmptySubtree[d+1], EmptySubtree[d+1])
	}
}

// SMTKey returns the 256-bit leaf key for canonical fqdn.
func SMTKey(fqdn string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(smtKeyDomain))
	_, _ = h.Write([]byte(fqdn))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// OccupiedLeafHash computes SHA256(0x00 || k || SHA256(canonicalLeaf)).
func OccupiedLeafHash(key [32]byte, canonicalLeaf []byte) [32]byte {
	leafDigest := sha256.Sum256(canonicalLeaf)
	h := sha256.New()
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(key[:])
	_, _ = h.Write(leafDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// InternalNodeHash computes SHA256(0x01 || left || right).
func InternalNodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SMTBit returns bit d (0 at MSB root, 255 at leaf) of key.
func SMTBit(key [32]byte, depth int) bool {
	return ((key[depth/8] >> uint(7-(depth%8))) & 1) == 1
}

// SMTProof is the bitmask-compressed inclusion/exclusion proof for one 256-bit leaf key.
type SMTProof struct {
	NonEmptyBitmap [32]byte
	Siblings       [][32]byte
}

// MarshalBinary encodes NonEmptyBitmap followed by popcount 32-byte sibling hashes in root-to-leaf order.
func (p SMTProof) MarshalBinary() ([]byte, error) {
	pop := bitmapPopcount(p.NonEmptyBitmap)
	if len(p.Siblings) != pop {
		return nil, fmt.Errorf("%w: bitmap popcount %d != siblings %d", ErrInvalidSMTProof, pop, len(p.Siblings))
	}
	out := make([]byte, 32+pop*32)
	copy(out[:32], p.NonEmptyBitmap[:])
	for i, sib := range p.Siblings {
		copy(out[32+i*32:64+i*32], sib[:])
	}
	return out, nil
}

// UnmarshalSMTProof decodes SMTProof v1 and rejects trailing or canonical-violating empty siblings.
func UnmarshalSMTProof(data []byte) (SMTProof, error) {
	if len(data) < 32 {
		return SMTProof{}, fmt.Errorf("%w: truncated bitmap", ErrInvalidSMTProof)
	}
	var proof SMTProof
	copy(proof.NonEmptyBitmap[:], data[:32])
	pop := bitmapPopcount(proof.NonEmptyBitmap)
	expectedLen := 32 + pop*32
	if len(data) != expectedLen {
		return SMTProof{}, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidSMTProof, len(data), expectedLen)
	}
	proof.Siblings = make([][32]byte, pop)
	for i := range pop {
		copy(proof.Siblings[i][:], data[32+i*32:64+i*32])
	}
	if err := proof.validateCanonical(); err != nil {
		return SMTProof{}, err
	}
	return proof, nil
}

func (p SMTProof) validateCanonical() error {
	pop := bitmapPopcount(p.NonEmptyBitmap)
	if len(p.Siblings) != pop {
		return fmt.Errorf("%w: bitmap popcount %d != siblings %d", ErrInvalidSMTProof, pop, len(p.Siblings))
	}
	sibIdx := 0
	for d := range smtDepth {
		if SMTBit(p.NonEmptyBitmap, d) {
			if p.Siblings[sibIdx] == EmptySubtree[d+1] {
				return fmt.Errorf("%w: non-empty bit set for empty subtree at depth %d", ErrInvalidSMTProof, d)
			}
			sibIdx++
		}
	}
	return nil
}

// ComputeSMTRoot computes the 256-bit SMT root implied by key, leafHash, and proof.
func ComputeSMTRoot(key [32]byte, leafHash [32]byte, proof SMTProof) ([32]byte, error) {
	if err := proof.validateCanonical(); err != nil {
		return [32]byte{}, err
	}
	var sibs [smtDepth][32]byte
	sibIdx := 0
	for d := range smtDepth {
		if SMTBit(proof.NonEmptyBitmap, d) {
			sibs[d] = proof.Siblings[sibIdx]
			sibIdx++
		} else {
			sibs[d] = EmptySubtree[d+1]
		}
	}
	cur := leafHash
	for d := smtDepth - 1; d >= 0; d-- {
		if SMTBit(key, d) {
			cur = InternalNodeHash(sibs[d], cur)
		} else {
			cur = InternalNodeHash(cur, sibs[d])
		}
	}
	return cur, nil
}

// VerifyInclusionProof verifies that canonicalLeaf at key authenticates to expectedRoot.
func VerifyInclusionProof(key [32]byte, canonicalLeaf []byte, proof SMTProof, expectedRoot [32]byte) error {
	root, err := ComputeSMTRoot(key, OccupiedLeafHash(key, canonicalLeaf), proof)
	if err != nil {
		return err
	}
	if root != expectedRoot {
		return fmt.Errorf("%w: root mismatch", ErrInvalidSMTProof)
	}
	return nil
}

// BatchMultiproof authenticates pre-state values for a strictly increasing batch
// of keys (k_1 < ... < k_b) and supports deterministic post-state root recomputation.
type BatchMultiproof struct {
	BitCount       uint32
	NonEmptyBitmap []byte
	Siblings       [][32]byte
}

// BatchUpdate pairs a sorted leaf key with its prior hash and new hash.
type BatchUpdate struct {
	Key     [32]byte
	OldHash [32]byte
	NewHash [32]byte
}

// MarshalBinary serializes a BatchMultiproof.
func (m BatchMultiproof) MarshalBinary() ([]byte, error) {
	if err := m.validateSizes(); err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(m.NonEmptyBitmap)+len(m.Siblings)*32)
	binary.BigEndian.PutUint32(out[:4], m.BitCount)
	copy(out[4:4+len(m.NonEmptyBitmap)], m.NonEmptyBitmap)
	off := 4 + len(m.NonEmptyBitmap)
	for _, sib := range m.Siblings {
		copy(out[off:off+32], sib[:])
		off += 32
	}
	return out, nil
}

// UnmarshalBatchMultiproof decodes a BatchMultiproof, rejecting extra bits or trailing bytes.
func UnmarshalBatchMultiproof(data []byte) (BatchMultiproof, error) {
	m, consumed, err := decodeBatchMultiproofPrefix(data)
	if err != nil {
		return BatchMultiproof{}, err
	}
	if consumed != len(data) {
		return BatchMultiproof{}, fmt.Errorf("%w: %d trailing bytes in multiproof", ErrInvalidSMTProof, len(data)-consumed)
	}
	return m, nil
}

func decodeBatchMultiproofPrefix(data []byte) (BatchMultiproof, int, error) {
	if len(data) < 4 {
		return BatchMultiproof{}, 0, fmt.Errorf("%w: truncated multiproof header", ErrInvalidSMTProof)
	}
	bitCount := binary.BigEndian.Uint32(data[:4])
	if bitCount > MaxBatchSize*smtDepth {
		return BatchMultiproof{}, 0, fmt.Errorf("%w: multiproof bitcount %d exceeds bound", ErrInvalidSMTProof, bitCount)
	}
	bitmapBytes := int((bitCount + 7) / 8)
	if len(data) < 4+bitmapBytes {
		return BatchMultiproof{}, 0, fmt.Errorf("%w: truncated multiproof bitmap", ErrInvalidSMTProof)
	}
	bitmap := append([]byte(nil), data[4:4+bitmapBytes]...)
	if rem := bitCount % 8; rem != 0 {
		mask := byte((1 << (8 - rem)) - 1)
		if bitmap[len(bitmap)-1]&mask != 0 {
			return BatchMultiproof{}, 0, fmt.Errorf("%w: non-zero padding bits in multiproof bitmap", ErrInvalidSMTProof)
		}
	}
	pop := 0
	for _, b := range bitmap {
		pop += bits.OnesCount8(b)
	}
	off := 4 + bitmapBytes
	if len(data) < off+pop*32 {
		return BatchMultiproof{}, 0, fmt.Errorf("%w: truncated multiproof siblings", ErrInvalidSMTProof)
	}
	siblings := make([][32]byte, pop)
	for i := range pop {
		copy(siblings[i][:], data[off:off+32])
		off += 32
	}
	return BatchMultiproof{
		BitCount:       bitCount,
		NonEmptyBitmap: bitmap,
		Siblings:       siblings,
	}, off, nil
}

func (m BatchMultiproof) validateSizes() error {
	expectedBytes := int((m.BitCount + 7) / 8)
	if len(m.NonEmptyBitmap) != expectedBytes {
		return fmt.Errorf("%w: bitmap byte len %d != %d", ErrInvalidSMTProof, len(m.NonEmptyBitmap), expectedBytes)
	}
	pop := 0
	for _, b := range m.NonEmptyBitmap {
		pop += bits.OnesCount8(b)
	}
	if len(m.Siblings) != pop {
		return fmt.Errorf("%w: multiproof popcount %d != siblings %d", ErrInvalidSMTProof, pop, len(m.Siblings))
	}
	return nil
}

// VerifyAndApplyMultiproof verifies that all BatchUpdate.OldHash values authenticate
// against expectedPrevRoot and computes the resulting post-state SMT root using NewHash.
func VerifyAndApplyMultiproof(updates []BatchUpdate, proof BatchMultiproof, expectedPrevRoot [32]byte) ([32]byte, error) {
	if err := proof.validateSizes(); err != nil {
		return [32]byte{}, err
	}
	if len(updates) == 0 {
		if proof.BitCount != 0 || len(proof.Siblings) != 0 {
			return [32]byte{}, fmt.Errorf("%w: empty batch must carry empty multiproof", ErrInvalidSMTProof)
		}
		return expectedPrevRoot, nil
	}
	for i := 1; i < len(updates); i++ {
		if bytes.Compare(updates[i-1].Key[:], updates[i].Key[:]) >= 0 {
			return [32]byte{}, fmt.Errorf("%w: batch keys not strictly ascending", ErrInvalidSMTProof)
		}
	}
	cursor := &multiproofCursor{proof: proof}
	oldRoot, newRoot, err := cursor.walk(0, updates)
	if err != nil {
		return [32]byte{}, err
	}
	if cursor.bitIdx != int(proof.BitCount) || cursor.sibIdx != len(proof.Siblings) {
		return [32]byte{}, fmt.Errorf("%w: unconsumed multiproof data", ErrInvalidSMTProof)
	}
	if oldRoot != expectedPrevRoot {
		return [32]byte{}, fmt.Errorf("%w: pre-state root mismatch", ErrInvalidSMTProof)
	}
	return newRoot, nil
}

type multiproofCursor struct {
	proof  BatchMultiproof
	bitIdx int
	sibIdx int
}

func (c *multiproofCursor) nextSibling(depth int) ([32]byte, error) {
	if c.bitIdx >= int(c.proof.BitCount) {
		return [32]byte{}, fmt.Errorf("%w: multiproof bitmap exhausted", ErrInvalidSMTProof)
	}
	nonEmpty := ((c.proof.NonEmptyBitmap[c.bitIdx/8] >> uint(7-(c.bitIdx%8))) & 1) == 1
	c.bitIdx++
	if !nonEmpty {
		return EmptySubtree[depth+1], nil
	}
	if c.sibIdx >= len(c.proof.Siblings) {
		return [32]byte{}, fmt.Errorf("%w: multiproof siblings exhausted", ErrInvalidSMTProof)
	}
	sib := c.proof.Siblings[c.sibIdx]
	c.sibIdx++
	if sib == EmptySubtree[depth+1] {
		return [32]byte{}, fmt.Errorf("%w: non-empty bit set for empty subtree at depth %d", ErrInvalidSMTProof, depth)
	}
	return sib, nil
}

func (c *multiproofCursor) walk(depth int, items []BatchUpdate) ([32]byte, [32]byte, error) {
	if depth == smtDepth {
		return items[0].OldHash, items[0].NewHash, nil
	}
	split := partitionUpdates(items, depth)
	left, right := items[:split], items[split:]
	switch {
	case len(left) > 0 && len(right) > 0:
		oldL, newL, err := c.walk(depth+1, left)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		oldR, newR, err := c.walk(depth+1, right)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return InternalNodeHash(oldL, oldR), InternalNodeHash(newL, newR), nil
	case len(left) > 0:
		sib, err := c.nextSibling(depth)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		oldL, newL, err := c.walk(depth+1, left)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return InternalNodeHash(oldL, sib), InternalNodeHash(newL, sib), nil
	default:
		sib, err := c.nextSibling(depth)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		oldR, newR, err := c.walk(depth+1, right)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return InternalNodeHash(sib, oldR), InternalNodeHash(sib, newR), nil
	}
}

func partitionUpdates(items []BatchUpdate, depth int) int {
	for i := range items {
		if SMTBit(items[i].Key, depth) {
			return i
		}
	}
	return len(items)
}

// SparseMerkleTree is an in-memory path-compressed 256-bit Portal Name Tree.
type SparseMerkleTree struct {
	root *smtNode
}

type smtNode struct {
	isLeaf        bool
	key           [32]byte
	leafHash      [32]byte
	canonicalLeaf []byte
	left          *smtNode
	right         *smtNode
	hash          [32]byte
}

// NewSparseMerkleTree creates an empty 256-bit Sparse Merkle Tree.
func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{}
}

// Root returns the current 32-byte SMT root hash.
func (t *SparseMerkleTree) Root() [32]byte {
	if t == nil || t.root == nil {
		return EmptySubtree[0]
	}
	return t.root.hash
}

// Get returns a copy of the stored canonical leaf bytes for key, if present.
func (t *SparseMerkleTree) Get(key [32]byte) ([]byte, bool) {
	if t == nil || t.root == nil {
		return nil, false
	}
	n := t.root
	for d := 0; n != nil && d <= smtDepth; d++ {
		if n.isLeaf {
			if n.key == key {
				return append([]byte(nil), n.canonicalLeaf...), true
			}
			return nil, false
		}
		if SMTBit(key, d) {
			n = n.right
		} else {
			n = n.left
		}
	}
	return nil, false
}

// Put inserts or replaces the canonical leaf bytes at key and updates all ancestor hashes.
func (t *SparseMerkleTree) Put(key [32]byte, canonicalLeaf []byte) {
	leafCopy := append([]byte(nil), canonicalLeaf...)
	leafHash := OccupiedLeafHash(key, leafCopy)
	t.root = t.insert(t.root, 0, key, leafHash, leafCopy)
}

func (t *SparseMerkleTree) insert(n *smtNode, depth int, key, leafHash [32]byte, canonicalLeaf []byte) *smtNode {
	if n == nil {
		return &smtNode{
			isLeaf:        true,
			key:           key,
			leafHash:      leafHash,
			canonicalLeaf: canonicalLeaf,
			hash:          compressedLeafSubtreeHash(depth, key, leafHash),
		}
	}
	if n.isLeaf {
		if n.key == key {
			return &smtNode{
				isLeaf:        true,
				key:           key,
				leafHash:      leafHash,
				canonicalLeaf: canonicalLeaf,
				hash:          compressedLeafSubtreeHash(depth, key, leafHash),
			}
		}
		return t.splitLeaf(n, depth, key, leafHash, canonicalLeaf)
	}
	if SMTBit(key, depth) {
		n.right = t.insert(n.right, depth+1, key, leafHash, canonicalLeaf)
	} else {
		n.left = t.insert(n.left, depth+1, key, leafHash, canonicalLeaf)
	}
	n.hash = InternalNodeHash(childHash(n.left, depth+1), childHash(n.right, depth+1))
	return n
}

func (t *SparseMerkleTree) splitLeaf(existing *smtNode, depth int, key, leafHash [32]byte, canonicalLeaf []byte) *smtNode {
	existingBit := SMTBit(existing.key, depth)
	newBit := SMTBit(key, depth)
	branch := &smtNode{}
	if existingBit == newBit {
		sub := t.splitLeaf(existing, depth+1, key, leafHash, canonicalLeaf)
		if existingBit {
			branch.right = sub
		} else {
			branch.left = sub
		}
	} else {
		newNode := &smtNode{
			isLeaf:        true,
			key:           key,
			leafHash:      leafHash,
			canonicalLeaf: canonicalLeaf,
			hash:          compressedLeafSubtreeHash(depth+1, key, leafHash),
		}
		existing.hash = compressedLeafSubtreeHash(depth+1, existing.key, existing.leafHash)
		if newBit {
			branch.left = existing
			branch.right = newNode
		} else {
			branch.left = newNode
			branch.right = existing
		}
	}
	branch.hash = InternalNodeHash(childHash(branch.left, depth+1), childHash(branch.right, depth+1))
	return branch
}

// Prove generates a single-key SMTProof v1 against the current tree root.
func (t *SparseMerkleTree) Prove(key [32]byte) (SMTProof, error) {
	var proof SMTProof
	n := t.root
	for d := range smtDepth {
		if n == nil {
			break
		}
		if n.isLeaf {
			if n.key == key {
				break
			}
			// Existing compressed leaf sits on the opposite side where it diverges from key.
			diffDepth := firstDiffDepth(key, n.key, d)
			setBitmapBit(&proof.NonEmptyBitmap, diffDepth)
			proof.Siblings = append(proof.Siblings, compressedLeafSubtreeHash(diffDepth+1, n.key, n.leafHash))
			break
		}
		var sibHash [32]byte
		if SMTBit(key, d) {
			sibHash = childHash(n.left, d+1)
			n = n.right
		} else {
			sibHash = childHash(n.right, d+1)
			n = n.left
		}
		if sibHash != EmptySubtree[d+1] {
			setBitmapBit(&proof.NonEmptyBitmap, d)
			proof.Siblings = append(proof.Siblings, sibHash)
		}
	}
	return proof, nil
}

// ProvePreStateBatch generates a BatchMultiproof covering sortedKeys against the
// current tree state, returning each key's stored prior canonical leaf bytes (or nil if empty).
func (t *SparseMerkleTree) ProvePreStateBatch(sortedKeys [][32]byte) ([][]byte, BatchMultiproof, error) {
	for i := 1; i < len(sortedKeys); i++ {
		if bytes.Compare(sortedKeys[i-1][:], sortedKeys[i][:]) >= 0 {
			return nil, BatchMultiproof{}, fmt.Errorf("%w: keys not strictly sorted", ErrInvalidSMTProof)
		}
	}
	prevLeaves := make([][]byte, len(sortedKeys))
	if len(sortedKeys) == 0 {
		return prevLeaves, BatchMultiproof{}, nil
	}
	for i, k := range sortedKeys {
		if raw, ok := t.Get(k); ok {
			prevLeaves[i] = raw
		}
	}
	builder := &multiproofBuilder{}
	builder.collect(t.root, 0, sortedKeys)
	return prevLeaves, builder.finish(), nil
}

type multiproofBuilder struct {
	bits     []byte
	bitCount uint32
	siblings [][32]byte
}

func (b *multiproofBuilder) pushBit(nonEmpty bool) {
	if int(b.bitCount/8) >= len(b.bits) {
		b.bits = append(b.bits, 0)
	}
	if nonEmpty {
		b.bits[b.bitCount/8] |= 1 << uint(7-(b.bitCount%8))
	}
	b.bitCount++
}

func (b *multiproofBuilder) collect(n *smtNode, depth int, keys [][32]byte) {
	if depth == smtDepth {
		return
	}
	split := partitionKeys(keys, depth)
	leftKeys, rightKeys := keys[:split], keys[split:]
	var leftNode, rightNode *smtNode
	if n != nil {
		if n.isLeaf {
			if SMTBit(n.key, depth) {
				rightNode = n
			} else {
				leftNode = n
			}
		} else {
			leftNode = n.left
			rightNode = n.right
		}
	}
	switch {
	case len(leftKeys) > 0 && len(rightKeys) > 0:
		b.collect(leftNode, depth+1, leftKeys)
		b.collect(rightNode, depth+1, rightKeys)
	case len(leftKeys) > 0:
		sib := nodeHashAt(rightNode, depth+1)
		if sib == EmptySubtree[depth+1] {
			b.pushBit(false)
		} else {
			b.pushBit(true)
			b.siblings = append(b.siblings, sib)
		}
		b.collect(leftNode, depth+1, leftKeys)
	default:
		sib := nodeHashAt(leftNode, depth+1)
		if sib == EmptySubtree[depth+1] {
			b.pushBit(false)
		} else {
			b.pushBit(true)
			b.siblings = append(b.siblings, sib)
		}
		b.collect(rightNode, depth+1, rightKeys)
	}
}

func (b *multiproofBuilder) finish() BatchMultiproof {
	return BatchMultiproof{
		BitCount:       b.bitCount,
		NonEmptyBitmap: b.bits,
		Siblings:       b.siblings,
	}
}

func partitionKeys(keys [][32]byte, depth int) int {
	for i := range keys {
		if SMTBit(keys[i], depth) {
			return i
		}
	}
	return len(keys)
}

func nodeHashAt(n *smtNode, depth int) [32]byte {
	if n == nil {
		return EmptySubtree[depth]
	}
	if n.isLeaf {
		return compressedLeafSubtreeHash(depth, n.key, n.leafHash)
	}
	return n.hash
}

func compressedLeafSubtreeHash(depth int, key, leafHash [32]byte) [32]byte {
	cur := leafHash
	for d := smtDepth - 1; d >= depth; d-- {
		if SMTBit(key, d) {
			cur = InternalNodeHash(EmptySubtree[d+1], cur)
		} else {
			cur = InternalNodeHash(cur, EmptySubtree[d+1])
		}
	}
	return cur
}

func childHash(n *smtNode, depth int) [32]byte {
	if n == nil {
		return EmptySubtree[depth]
	}
	return n.hash
}

func firstDiffDepth(a, b [32]byte, start int) int {
	for d := start; d < smtDepth; d++ {
		if SMTBit(a, d) != SMTBit(b, d) {
			return d
		}
	}
	return smtDepth
}

func setBitmapBit(bitmap *[32]byte, depth int) {
	bitmap[depth/8] |= 1 << uint(7-(depth%8))
}

func bitmapPopcount(bitmap [32]byte) int {
	total := 0
	for _, b := range bitmap {
		total += bits.OnesCount8(b)
	}
	return total
}
