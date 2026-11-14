package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

func testBatchCreateAndLog(t *testing.T, zone string, epoch, ts uint64) (pgns.BatchTransitionProof, [32]byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("owner-key"))
	owner := secp256k1.PrivKeyFromBytes(seed[:])
	var pub33 [33]byte
	copy(pub33[:], owner.PubKey().SerializeCompressed())
	tag, err := pgns.DeriveIDTag(pub33)
	if err != nil {
		t.Fatal(err)
	}
	fqdn := "web." + tag + ".id." + zone
	leaf := pgns.PortalLeafRecord{
		Version:       pgns.LeafVersion,
		Flags:         pgns.FlagHTTP2,
		FQDN:          fqdn,
		Seq:           1,
		IssuedAt:      ts,
		ExpiresAt:     ts + 3600,
		OwnerPubKey:   pub33,
		TLSSPKISHA256: sha256.Sum256([]byte("cert")),
		Endpoints: []pgns.Endpoint{{
			RelayID:  [20]byte{1},
			IPv4:     [4]byte{93, 184, 216, 34},
			Port:     443,
			Priority: 10,
		}},
	}
	rawLeaf, err := leaf.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	tx := pgns.LeafTx{
		TxType:   pgns.TxTypeCreate,
		Leaf:     leaf,
		PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, rawLeaf, pgns.PoWDifficultyID),
	}
	if err := tx.SignOwner(owner); err != nil {
		t.Fatal(err)
	}
	smt := pgns.NewSparseMerkleTree()
	k := pgns.SMTKey(fqdn)
	prevLeaves, mp, err := smt.ProvePreStateBatch([][32]byte{k})
	if err != nil {
		t.Fatal(err)
	}
	smt.Put(k, rawLeaf)
	batchBytes, err := pgns.CanonicalBatchBytes([]pgns.LeafTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	recHash := pgns.EpochRecordHash(epoch, ts, smt.Root(), batchBytes)
	logRoot, _, err := pgns.ComputeAppendLogRoot(0, recHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pgns.BatchTransitionProof{
		Zone:        zone,
		Epoch:       epoch,
		Timestamp:   ts,
		PrevSMTRoot: pgns.EmptySubtree[0],
		NewSMTRoot:  smt.Root(),
		NewLogRoot:  logRoot,
		TxEntries:   []pgns.LeafTx{tx},
		PrevLeaves:  prevLeaves,
		PreStateMP:  mp,
	}, logRoot
}

// INV: Witness persists an exact 88-byte checkpoint across restarts, cosigns valid
// transitions via HTTP, and rejects epoch rollbacks or forged state roots without
// corrupting persisted state.
func TestWitnessPersistenceAndHTTPVerification(t *testing.T) {
	now := int64(1_700_000_000)
	seed := sha256.Sum256([]byte("witness-1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	statePath := filepath.Join(t.TempDir(), "witness.state")

	w, err := New(Config{
		Name:       "w1.pgns.example",
		PrivateKey: priv,
		StatePath:  statePath,
		Now:        func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatalf("New witness: %v", err)
	}

	batch0, logRoot0 := testBatchCreateAndLog(t, "portal.example", 0, uint64(now))
	wire0, err := batch0.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Forged SMT root via HTTP MUST return 422 and leave state absent.
	forgedBatch := batch0
	forgedBatch.NewSMTRoot[0] ^= 0xff
	forgedWire, _ := forgedBatch.MarshalBinary()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/cosign", bytes.NewReader(forgedWire))
	w.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("forged batch status = %d, want 422", rec.Code)
	}
	if _, ok := w.State(); ok {
		t.Fatal("forged batch must not initialize witness state")
	}

	// Valid genesis batch returns 200 OK + C2SP cosignature and persists exact 88 bytes.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cosign", bytes.NewReader(wire0))
	w.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("genesis batch status = %d body=%s", rec.Code, rec.Body.String())
	}
	stat, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat statePath: %v", err)
	}
	if stat.Size() != pgns.WitnessStateBytes {
		t.Fatalf("persisted state size = %d, want %d", stat.Size(), pgns.WitnessStateBytes)
	}

	// Verify returned cosignature verifies under WitnessSet(threshold=1).
	cpBody := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + "portal.example",
		LogSize:   1,
		LogRoot:   logRoot0,
		Epoch:     0,
		Timestamp: uint64(now),
		SMTRoot:   batch0.NewSMTRoot,
	}.FormatBody()
	signed := append(append([]byte(nil), cpBody...), '\n')
	signed = append(signed, rec.Body.Bytes()...)
	ws := pgns.WitnessSet{Threshold: 1, Witnesses: []pgns.WitnessKey{w.Key()}}
	if _, _, err := pgns.ParseAndVerifySignedCheckpoint(signed, "portal.example", ws); err != nil {
		t.Fatalf("ParseAndVerifySignedCheckpoint: %v", err)
	}

	// Reload Witness from 88-byte state file and verify replay of epoch 0 returns 409 Conflict.
	w2, err := New(Config{
		Name:       "w1.pgns.example",
		PrivateKey: priv,
		StatePath:  statePath,
		Now:        func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatalf("reload witness: %v", err)
	}
	st, ok := w2.State()
	if !ok || st.Epoch != 0 || st.LogRoot != logRoot0 {
		t.Fatalf("reloaded state mismatch: ok=%v st=%+v", ok, st)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/cosign", bytes.NewReader(wire0))
	w2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replay epoch 0 status = %d, want 409", rec.Code)
	}

	// Verify GET /state returns 88 bytes matching state.
	rec = httptest.NewRecorder()
	w2.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/state", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != pgns.WitnessStateBytes {
		t.Fatalf("GET /state code=%d len=%d", rec.Code, rec.Body.Len())
	}
	_ = tlog.HashSize
}
