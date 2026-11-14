// Package witness implements the 88-byte stateless PGNS transition-verifying witness.
package witness

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

const maxCosignRequestBytes = 4 << 20 // 4 MiB

var (
	errEpochConflict = errors.New("witness: epoch conflicts with persisted state")
)

// Config configures a stateless PGNS witness node.
type Config struct {
	Name       string
	PrivateKey ed25519.PrivateKey
	StatePath  string
	Now        func() time.Time
}

// Witness verifies PGNS epoch transitions against an 88-byte persistent checkpoint
// and returns deterministic C2SP cosignature/v1 signatures.
type Witness struct {
	mu        sync.Mutex
	key       pgns.WitnessKey
	priv      ed25519.PrivateKey
	statePath string
	nowFn     func() time.Time
	hasState  bool
	state     pgns.WitnessState
}

// New initializes a Witness, loading any persisted 88-byte checkpoint from cfg.StatePath.
func New(cfg Config) (*Witness, error) {
	if cfg.Name == "" || len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("witness: valid name and Ed25519 private key are required")
	}
	pub, ok := cfg.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("witness: invalid Ed25519 public key")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	w := &Witness{
		key:       pgns.WitnessKey{Name: cfg.Name, PublicKey: pub},
		priv:      append(ed25519.PrivateKey(nil), cfg.PrivateKey...),
		statePath: cfg.StatePath,
		nowFn:     nowFn,
	}
	if cfg.StatePath != "" {
		raw, err := os.ReadFile(cfg.StatePath)
		if err == nil {
			st, parseErr := pgns.UnmarshalWitnessState(raw)
			if parseErr != nil {
				return nil, fmt.Errorf("witness: corrupt persisted state: %w", parseErr)
			}
			w.state = st
			w.hasState = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("witness: read state: %w", err)
		}
	}
	return w, nil
}

// Key returns the public WitnessKey descriptor for inclusion in a WitnessSet.
func (w *Witness) Key() pgns.WitnessKey {
	return w.key
}

// State returns the last persisted 88-byte checkpoint state, if initialized.
func (w *Witness) State() (pgns.WitnessState, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state, w.hasState
}

// VerifyAndCosign executes the 5-step stateless verification on b, atomically
// persists the resulting 88-byte WitnessState, and returns a C2SP cosignature.
func (w *Witness) VerifyAndCosign(b pgns.BatchTransitionProof) (pgns.WitnessCosignature, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var prevPtr *pgns.WitnessState
	if w.hasState {
		if b.Epoch <= w.state.Epoch {
			return pgns.WitnessCosignature{}, fmt.Errorf("%w: got epoch %d, current %d", errEpochConflict, b.Epoch, w.state.Epoch)
		}
		prev := w.state
		prevPtr = &prev
	}

	nowSec := uint64(max(0, w.nowFn().UTC().Unix()))
	nextState, err := pgns.VerifyBatchTransition(prevPtr, b, nowSec)
	if err != nil {
		return pgns.WitnessCosignature{}, err
	}

	cp := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + b.Zone,
		LogSize:   nextState.LogSize,
		LogRoot:   nextState.LogRoot,
		Epoch:     nextState.Epoch,
		Timestamp: nextState.Timestamp,
		SMTRoot:   nextState.SMTRoot,
	}
	cosig, err := pgns.CosignCheckpoint(cp.FormatBody(), w.key, w.priv, b.Timestamp)
	if err != nil {
		return pgns.WitnessCosignature{}, err
	}
	if w.statePath != "" {
		if err := persistWitnessStateAtomic(w.statePath, nextState.MarshalBinary()); err != nil {
			return pgns.WitnessCosignature{}, err
		}
	}
	w.state = nextState
	w.hasState = true
	return cosig, nil
}

func persistWitnessStateAtomic(path string, encoded [pgns.WitnessStateBytes]byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("witness: mkdir state dir: %w", err)
	}
	f, err := os.CreateTemp(dir, ".witness-state-*")
	if err != nil {
		return fmt.Errorf("witness: create temp state: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("witness: chmod temp state: %w", err)
	}
	_, writeErr := f.Write(encoded[:])
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("witness: persist state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("witness: rename state: %w", err)
	}
	return nil
}

// Handler returns the HTTP endpoint serving POST /v1/cosign, GET /state, and GET /healthz.
func (w *Witness) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cosign", w.handleCosign)
	mux.HandleFunc("GET /state", w.handleState)
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok\n"))
	})
	return mux
}

func (w *Witness) handleCosign(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCosignRequestBytes+1))
	if err != nil {
		http.Error(rw, "read body failed", http.StatusBadRequest)
		return
	}
	if len(body) > maxCosignRequestBytes {
		http.Error(rw, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	batch, err := pgns.UnmarshalBatchTransitionProof(body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	cosig, err := w.VerifyAndCosign(batch)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, errEpochConflict) {
			status = http.StatusConflict
		}
		http.Error(rw, err.Error(), status)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte(cosig.FormatLine() + "\n"))
}

func (w *Witness) handleState(rw http.ResponseWriter, r *http.Request) {
	st, ok := w.State()
	if !ok {
		http.NotFound(rw, r)
		return
	}
	raw := st.MarshalBinary()
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(raw[:])
}
