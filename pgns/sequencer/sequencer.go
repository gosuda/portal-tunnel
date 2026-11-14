// Package sequencer implements the PGNS mempool, epoch bundler, C2SP tile archive, and witness quorum collector.
package sequencer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

const (
	// TileHeight is the C2SP tlog-tiles Merkle tile height (256 hashes per tile).
	TileHeight = 8

	defaultActiveInterval    = time.Second
	defaultHeartbeatInterval = 60 * time.Second
	maxUpdatesPerMinute      = 6
	updateRateWindowSec      = 60
	maxSubmitBodyBytes       = 64 << 10
	maxCosignRespBytes       = 4 << 10
)

var (
	// ErrRateLimited marks excessive TxTypeUpdate submissions for one FQDN (> 6/min).
	ErrRateLimited = errors.New("sequencer: per-fqdn update rate limit exceeded")
	// ErrQuorumFailed marks an epoch sealing attempt that gathered fewer than k witness cosignatures.
	ErrQuorumFailed = errors.New("sequencer: insufficient witness cosignatures")
)

// Config configures a PGNS Sequencer instance.
type Config struct {
	Zone              string
	WitnessSet        pgns.WitnessSet
	WitnessEndpoints  []string
	HTTPClient        *http.Client
	ActiveInterval    time.Duration
	HeartbeatInterval time.Duration
	Now               func() time.Time
}

type pendingTx struct {
	tx      pgns.LeafTx
	key     [32]byte
	addedAt uint64
}

// Sequencer validates LeafTx submissions, bundles them into epochs, collects k-of-m
// witness cosignatures, and serves C2SP tiles, batches, checkpoints, and ResolveBundles.
type Sequencer struct {
	zone              string
	witnessSet        pgns.WitnessSet
	witnessEndpoints  []string
	httpClient        *http.Client
	activeInterval    time.Duration
	heartbeatInterval time.Duration
	nowFn             func() time.Time

	mu               sync.Mutex
	sealMu           sync.Mutex
	smt              *pgns.SparseMerkleTree
	logHashes        []tlog.Hash
	hasEpoch         bool
	nextEpoch        uint64
	lastTimestamp    uint64
	lastLogRoot      [32]byte
	lastSMTRoot      [32]byte
	latestCheckpoint []byte
	batches          map[uint64][]byte
	pending          map[string]pendingTx
	updateHistory    map[string][]uint64
}

// New constructs a PGNS Sequencer bound to cfg.Zone and cfg.WitnessSet.
func New(cfg Config) (*Sequencer, error) {
	normZone, err := pgns.NormalizeZone(cfg.Zone)
	if err != nil {
		return nil, err
	}
	if cfg.WitnessSet.Threshold <= 0 || cfg.WitnessSet.Threshold > len(cfg.WitnessSet.Witnesses) {
		return nil, pgns.ErrInvalidCheckpoint
	}
	if len(cfg.WitnessEndpoints) < cfg.WitnessSet.Threshold {
		return nil, fmt.Errorf("%w: need at least %d witness endpoints, got %d", ErrQuorumFailed, cfg.WitnessSet.Threshold, len(cfg.WitnessEndpoints))
	}
	activeInterval := cfg.ActiveInterval
	if activeInterval <= 0 {
		activeInterval = defaultActiveInterval
	}
	heartbeatInterval := cfg.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = defaultHeartbeatInterval
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	endpoints := make([]string, len(cfg.WitnessEndpoints))
	for i, ep := range cfg.WitnessEndpoints {
		endpoints[i] = strings.TrimRight(strings.TrimSpace(ep), "/")
	}
	return &Sequencer{
		zone:              normZone,
		witnessSet:        cfg.WitnessSet,
		witnessEndpoints:  endpoints,
		httpClient:        httpClient,
		activeInterval:    activeInterval,
		heartbeatInterval: heartbeatInterval,
		nowFn:             nowFn,
		smt:               pgns.NewSparseMerkleTree(),
		batches:           make(map[uint64][]byte),
		pending:           make(map[string]pendingTx),
		updateHistory:     make(map[string][]uint64),
	}, nil
}

// Run drives active epoch bundling and 0-tx heartbeat epochs until ctx is cancelled.
func (s *Sequencer) Run(ctx context.Context) error {
	activeTicker := time.NewTicker(s.activeInterval)
	heartbeatTicker := time.NewTicker(s.heartbeatInterval)
	defer activeTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-activeTicker.C:
			if s.pendingCount() == 0 {
				continue
			}
			_ = s.SealEpoch(ctx)
		case <-heartbeatTicker.C:
			_ = s.SealEpoch(ctx)
		}
	}
}

func (s *Sequencer) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// SubmitTx validates a canonical LeafTx against current committed state and admits it to the mempool.
func (s *Sequencer) SubmitTx(rawTx []byte) error {
	tx, err := pgns.UnmarshalLeafTx(rawTx)
	if err != nil {
		return err
	}
	nowSec := uint64(max(0, s.nowFn().UTC().Unix()))

	s.mu.Lock()
	defer s.mu.Unlock()

	key := pgns.SMTKey(tx.Leaf.FQDN)
	prevPtr, err := s.currentLeafLocked(key)
	if err != nil {
		return err
	}
	if err := pgns.ValidateTransition(prevPtr, tx, nowSec, s.zone); err != nil {
		return err
	}
	if existing, exists := s.pending[tx.Leaf.FQDN]; exists {
		// ColdRecovery strictly preempts non-recovery pending transitions on the same FQDN.
		if existing.tx.TxType == pgns.TxTypeColdRecovery && tx.TxType != pgns.TxTypeColdRecovery {
			return pgns.ErrTransitionInvalid
		}
	}
	if tx.TxType == pgns.TxTypeUpdate {
		if !s.allowUpdateLocked(tx.Leaf.FQDN, nowSec) {
			return ErrRateLimited
		}
	}
	s.pending[tx.Leaf.FQDN] = pendingTx{tx: tx, key: key, addedAt: nowSec}
	return nil
}

func (s *Sequencer) currentLeafLocked(key [32]byte) (*pgns.PortalLeafRecord, error) {
	raw, ok := s.smt.Get(key)
	if !ok {
		return nil, nil
	}
	leaf, err := pgns.UnmarshalCanonicalLeaf(raw)
	if err != nil {
		return nil, err
	}
	return &leaf, nil
}

func (s *Sequencer) allowUpdateLocked(fqdn string, now uint64) bool {
	history := s.updateHistory[fqdn]
	cutoff := uint64(0)
	if now > updateRateWindowSec {
		cutoff = now - updateRateWindowSec
	}
	kept := history[:0]
	for _, ts := range history {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= maxUpdatesPerMinute {
		s.updateHistory[fqdn] = kept
		return false
	}
	s.updateHistory[fqdn] = append(kept, now)
	return true
}

// SealEpoch bundles queued transactions (or emits a 0-tx heartbeat), gathers a k-of-m
// witness quorum, and commits the resulting SMT, tlog, and signed checkpoint atomically.
func (s *Sequencer) SealEpoch(ctx context.Context) error {
	s.sealMu.Lock()
	defer s.sealMu.Unlock()

	plan, err := s.prepareEpochPlan()
	if err != nil {
		return err
	}
	batchWire, err := plan.batch.MarshalBinary()
	if err != nil {
		return err
	}
	signedCheckpoint, err := s.collectWitnessQuorum(ctx, plan.checkpointBody, batchWire)
	if err != nil {
		return err
	}
	return s.commitEpochPlan(plan, batchWire, signedCheckpoint)
}

type epochPlan struct {
	epoch          uint64
	timestamp      uint64
	batch          pgns.BatchTransitionProof
	newLeaves      map[[32]byte][]byte
	addedLogHashes []tlog.Hash
	checkpointBody []byte
	includedFQDNs  []string
}

func (s *Sequencer) prepareEpochPlan() (epochPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := uint64(max(0, s.nowFn().UTC().Unix()))
	if s.hasEpoch && ts < s.lastTimestamp {
		ts = s.lastTimestamp
	}

	candidates := make([]pendingTx, 0, len(s.pending))
	for _, item := range s.pending {
		candidates = append(candidates, item)
	}
	// Prioritize ColdRecovery transactions before truncating to MaxBatchSize.
	sort.Slice(candidates, func(i, j int) bool {
		iCold := candidates[i].tx.TxType == pgns.TxTypeColdRecovery
		jCold := candidates[j].tx.TxType == pgns.TxTypeColdRecovery
		if iCold != jCold {
			return iCold
		}
		return bytes.Compare(candidates[i].key[:], candidates[j].key[:]) < 0
	})
	if len(candidates) > pgns.MaxBatchSize {
		candidates = candidates[:pgns.MaxBatchSize]
	}

	var valid []pendingTx
	for _, item := range candidates {
		prevPtr, err := s.currentLeafLocked(item.key)
		if err != nil {
			continue
		}
		if err := pgns.ValidateTransition(prevPtr, item.tx, ts, s.zone); err != nil {
			delete(s.pending, item.tx.Leaf.FQDN)
			continue
		}
		valid = append(valid, item)
	}
	// Witness Step 1 requires strictly ascending SMT leaf keys across the batch.
	sort.Slice(valid, func(i, j int) bool {
		return bytes.Compare(valid[i].key[:], valid[j].key[:]) < 0
	})

	sortedKeys := make([][32]byte, len(valid))
	txEntries := make([]pgns.LeafTx, len(valid))
	includedFQDNs := make([]string, len(valid))
	newLeaves := make(map[[32]byte][]byte, len(valid))
	for i, item := range valid {
		sortedKeys[i] = item.key
		txEntries[i] = item.tx
		includedFQDNs[i] = item.tx.Leaf.FQDN
		rawLeaf, err := item.tx.Leaf.MarshalCanonical()
		if err != nil {
			return epochPlan{}, err
		}
		newLeaves[item.key] = rawLeaf
	}

	prevLeaves, mp, err := s.smt.ProvePreStateBatch(sortedKeys)
	if err != nil {
		return epochPlan{}, err
	}
	updates := make([]pgns.BatchUpdate, len(valid))
	for i, item := range valid {
		oldH := pgns.EmptySubtree[256]
		if len(prevLeaves[i]) > 0 {
			oldH = pgns.OccupiedLeafHash(item.key, prevLeaves[i])
		}
		updates[i] = pgns.BatchUpdate{
			Key:     item.key,
			OldHash: oldH,
			NewHash: pgns.OccupiedLeafHash(item.key, newLeaves[item.key]),
		}
	}
	prevSMTRoot := s.smt.Root()
	if s.hasEpoch {
		prevSMTRoot = s.lastSMTRoot
	}
	newSMTRoot, err := pgns.VerifyAndApplyMultiproof(updates, mp, prevSMTRoot)
	if err != nil {
		return epochPlan{}, err
	}

	batchBytes, err := pgns.CanonicalBatchBytes(txEntries)
	if err != nil {
		return epochPlan{}, err
	}
	recHash := pgns.EpochRecordHash(s.nextEpoch, ts, newSMTRoot, batchBytes)
	newLogRoot, addedHashes, consProof, recProof, err := s.previewLogAppendLocked(recHash)
	if err != nil {
		return epochPlan{}, err
	}
	cp := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + s.zone,
		LogSize:   s.nextEpoch + 1,
		LogRoot:   newLogRoot,
		Epoch:     s.nextEpoch,
		Timestamp: ts,
		SMTRoot:   newSMTRoot,
	}
	return epochPlan{
		epoch:     s.nextEpoch,
		timestamp: ts,
		batch: pgns.BatchTransitionProof{
			Zone:              s.zone,
			Epoch:             s.nextEpoch,
			Timestamp:         ts,
			PrevLogRoot:       s.lastLogRoot,
			NewLogRoot:        newLogRoot,
			PrevSMTRoot:       prevSMTRoot,
			NewSMTRoot:        newSMTRoot,
			TxEntries:         txEntries,
			PrevLeaves:        prevLeaves,
			PreStateMP:        mp,
			ConsistencyProof:  consProof,
			AppendRecordProof: recProof,
		},
		newLeaves:      newLeaves,
		addedLogHashes: addedHashes,
		checkpointBody: cp.FormatBody(),
		includedFQDNs:  includedFQDNs,
	}, nil
}

func (s *Sequencer) previewLogAppendLocked(recHash [32]byte) ([32]byte, []tlog.Hash, tlog.TreeProof, tlog.RecordProof, error) {
	oldSize := s.nextEpoch
	hr := s.hashReaderForSlice(s.logHashes)
	newRoot, added, err := pgns.ComputeAppendLogRoot(oldSize, recHash, hr)
	if err != nil {
		return [32]byte{}, nil, nil, nil, err
	}
	if oldSize == 0 {
		return newRoot, added, nil, nil, nil
	}
	extended := append(append([]tlog.Hash(nil), s.logHashes...), added...)
	extReader := s.hashReaderForSlice(extended)
	consProof, err := tlog.ProveTree(int64(oldSize), int64(oldSize+1), extReader)
	if err != nil {
		return [32]byte{}, nil, nil, nil, fmt.Errorf("prove consistency: %w", err)
	}
	recProof, err := tlog.ProveRecord(int64(oldSize+1), int64(oldSize), extReader)
	if err != nil {
		return [32]byte{}, nil, nil, nil, fmt.Errorf("prove record inclusion: %w", err)
	}
	return newRoot, added, consProof, recProof, nil
}

func (s *Sequencer) hashReaderForSlice(hashes []tlog.Hash) tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < 0 || int(idx) >= len(hashes) {
				return nil, fmt.Errorf("hash index %d out of bounds (%d)", idx, len(hashes))
			}
			out[i] = hashes[idx]
		}
		return out, nil
	})
}

func (s *Sequencer) collectWitnessQuorum(ctx context.Context, checkpointBody, batchWire []byte) ([]byte, error) {
	results := make(chan string, len(s.witnessEndpoints))
	var wg sync.WaitGroup
	for _, endpoint := range s.witnessEndpoints {
		wg.Go(func() {
			line, err := s.postWitnessCosign(ctx, endpoint+"/v1/cosign", batchWire)
			if err == nil && line != "" {
				results <- line
			}
		})
	}
	wg.Wait()
	close(results)

	var sigLines []string
	for line := range results {
		sigLines = append(sigLines, line)
	}
	var assembled strings.Builder
	assembled.Write(checkpointBody)
	assembled.WriteByte('\n')
	for _, line := range sigLines {
		assembled.WriteString(line)
		assembled.WriteByte('\n')
	}
	noteBytes := []byte(assembled.String())
	_, verified, err := pgns.ParseAndVerifySignedCheckpoint(noteBytes, s.zone, s.witnessSet)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuorumFailed, err)
	}
	return pgns.FormatSignedCheckpoint(checkpointBody, verified), nil
}

func (s *Sequencer) postWitnessCosign(ctx context.Context, targetURL string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("witness returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCosignRespBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *Sequencer) commitEpochPlan(plan epochPlan, batchWire, signedCheckpoint []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if plan.epoch != s.nextEpoch {
		return fmt.Errorf("sequencer: epoch race (%d != %d)", plan.epoch, s.nextEpoch)
	}
	for k, leafRaw := range plan.newLeaves {
		s.smt.Put(k, leafRaw)
	}
	for _, fqdn := range plan.includedFQDNs {
		delete(s.pending, fqdn)
	}
	s.logHashes = append(s.logHashes, plan.addedLogHashes...)
	s.hasEpoch = true
	s.nextEpoch = plan.epoch + 1
	s.lastTimestamp = plan.timestamp
	s.lastLogRoot = plan.batch.NewLogRoot
	s.lastSMTRoot = plan.batch.NewSMTRoot
	s.latestCheckpoint = signedCheckpoint
	s.batches[plan.epoch] = batchWire
	return nil
}

// Resolve builds a CDN-cacheable self-verifying ResolveBundle for canonical fqdn.
func (s *Sequencer) Resolve(fqdn string) ([]byte, error) {
	normFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	key := pgns.SMTKey(normFQDN)

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.hasEpoch || len(s.latestCheckpoint) == 0 {
		return nil, pgns.ErrInvalidCheckpoint
	}
	rawLeaf, ok := s.smt.Get(key)
	if !ok {
		return nil, pgns.ErrInvalidLeaf
	}
	proof, err := s.smt.Prove(key)
	if err != nil {
		return nil, err
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return pgns.ResolveBundle{
		Leaf:             rawLeaf,
		InclusionProof:   proofBytes,
		SignedCheckpoint: s.latestCheckpoint,
	}.MarshalBinary()
}

// LatestCheckpoint returns a copy of the newest witness-cosigned checkpoint note.
func (s *Sequencer) LatestCheckpoint() ([]byte, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasEpoch {
		return nil, 0, false
	}
	return append([]byte(nil), s.latestCheckpoint...), s.nextEpoch - 1, true
}

// Batch returns a copy of the sealed canonical BatchTransitionProof for epoch.
func (s *Sequencer) Batch(epoch uint64) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.batches[epoch]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), raw...), true
}

// Handler serves /v1/submit, /v1/resolve/<fqdn>, /checkpoint, /batch/<epoch>, and /tiles/...
func (s *Sequencer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", s.handleSubmit)
	mux.HandleFunc("GET /v1/resolve/{fqdn}", s.handleResolve)
	mux.HandleFunc("GET /checkpoint", s.handleCheckpoint)
	mux.HandleFunc("GET /batch/{epoch}", s.handleBatch)
	mux.HandleFunc("GET /tiles/{path...}", s.handleTile)
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok\n"))
	})
	return mux
}

func (s *Sequencer) handleSubmit(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSubmitBodyBytes+1))
	if err != nil {
		http.Error(rw, "read body failed", http.StatusBadRequest)
		return
	}
	if len(body) > maxSubmitBodyBytes {
		http.Error(rw, "tx exceeds maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	if err := s.SubmitTx(body); err != nil {
		switch {
		case errors.Is(err, ErrRateLimited):
			http.Error(rw, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, pgns.ErrInvalidWire):
			http.Error(rw, err.Error(), http.StatusBadRequest)
		default:
			http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		}
		return
	}
	rw.WriteHeader(http.StatusAccepted)
}

func (s *Sequencer) handleResolve(rw http.ResponseWriter, r *http.Request) {
	fqdn := r.PathValue("fqdn")
	bundle, err := s.Resolve(fqdn)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Cache-Control", "public, max-age=15")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(bundle)
}

func (s *Sequencer) handleCheckpoint(rw http.ResponseWriter, r *http.Request) {
	cp, _, ok := s.LatestCheckpoint()
	if !ok {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Cache-Control", "public, max-age=5")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(cp)
}

func (s *Sequencer) handleBatch(rw http.ResponseWriter, r *http.Request) {
	epoch, err := strconv.ParseUint(r.PathValue("epoch"), 10, 64)
	if err != nil {
		http.Error(rw, "invalid epoch", http.StatusBadRequest)
		return
	}
	raw, ok := s.Batch(epoch)
	if !ok {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(raw)
}

func (s *Sequencer) handleTile(rw http.ResponseWriter, r *http.Request) {
	subpath := r.PathValue("path")
	tile, err := tlog.ParseTilePath(subpath)
	if err != nil || tile.H != TileHeight {
		http.NotFound(rw, r)
		return
	}
	s.mu.Lock()
	hashes := slices.Clone(s.logHashes)
	s.mu.Unlock()
	if !s.hasEpoch {
		http.NotFound(rw, r)
		return
	}
	data, err := tlog.ReadTileData(tile, s.hashReaderForSlice(hashes))
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(data)
}
