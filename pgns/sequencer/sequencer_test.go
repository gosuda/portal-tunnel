package sequencer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/pgns/witness"
)

func testKey(seed string) *secp256k1.PrivateKey {
	h := sha256.Sum256([]byte(seed))
	return secp256k1.PrivKeyFromBytes(h[:])
}

func pub33(k *secp256k1.PrivateKey) [33]byte {
	var out [33]byte
	copy(out[:], k.PubKey().SerializeCompressed())
	return out
}

// INV: Sequencer collects k-of-m witness cosignatures to seal epochs, serves
// verified ResolveBundles & C2SP tiles, prioritizes ColdRecovery over Update,
// and rate-limits Update submissions to <= 6/min per FQDN.
func TestSequencerLifecycleQuorumRateLimitAndTiles(t *testing.T) {
	const zone = "portal.example"
	now := int64(1_700_000_000)
	nowFn := func() time.Time { return time.Unix(now, 0) }

	// Spin up 3 stateless witnesses (threshold 2 of 3).
	var ws pgns.WitnessSet
	ws.Threshold = 2
	var endpoints []string
	for _, name := range []string{"w1", "w2", "w3"} {
		seed := sha256.Sum256([]byte("seq-witness:" + name))
		priv := ed25519.NewKeyFromSeed(seed[:])
		w, err := witness.New(witness.Config{Name: name, PrivateKey: priv, Now: nowFn})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(w.Handler())
		t.Cleanup(srv.Close)
		ws.Witnesses = append(ws.Witnesses, w.Key())
		endpoints = append(endpoints, srv.URL)
	}

	seq, err := New(Config{
		Zone:             zone,
		WitnessSet:       ws,
		WitnessEndpoints: endpoints,
		Now:              nowFn,
	})
	if err != nil {
		t.Fatalf("New sequencer: %v", err)
	}
	seqSrv := httptest.NewServer(seq.Handler())
	t.Cleanup(seqSrv.Close)

	owner := testKey("seq-owner-id")
	tag, _ := pgns.DeriveIDTag(pub33(owner))
	fqdn := "web." + tag + ".id." + zone

	leaf1 := pgns.PortalLeafRecord{
		Version:       pgns.LeafVersion,
		Flags:         pgns.FlagHTTP2,
		FQDN:          fqdn,
		Seq:           1,
		IssuedAt:      uint64(now),
		ExpiresAt:     uint64(now + 3600),
		OwnerPubKey:   pub33(owner),
		TLSSPKISHA256: sha256.Sum256([]byte("spki-1")),
		Endpoints: []pgns.Endpoint{{
			RelayID:  [20]byte{1},
			IPv4:     [4]byte{93, 184, 216, 34},
			Port:     443,
			Priority: 10,
		}},
	}
	rawLeaf1, _ := leaf1.MarshalCanonical()
	createTx := pgns.LeafTx{
		TxType:   pgns.TxTypeCreate,
		Leaf:     leaf1,
		PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, rawLeaf1, pgns.PoWDifficultyID),
	}
	_ = createTx.SignOwner(owner)
	createWire, _ := createTx.MarshalCanonical()

	resp, err := http.Post(seqSrv.URL+"/v1/submit", "application/octet-stream", bytes.NewReader(createWire))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /v1/submit status = %d, want 202", resp.StatusCode)
	}

	if err := seq.SealEpoch(context.Background()); err != nil {
		t.Fatalf("SealEpoch(0): %v", err)
	}

	// Verify /v1/resolve/<fqdn> returns self-verifying ResolveBundle with max-age=15.
	resResp, err := http.Get(seqSrv.URL + "/v1/resolve/" + fqdn)
	if err != nil {
		t.Fatal(err)
	}
	defer resResp.Body.Close()
	if resResp.StatusCode != http.StatusOK || resResp.Header.Get("Cache-Control") != "public, max-age=15" {
		t.Fatalf("resolve status=%d cache-control=%q", resResp.StatusCode, resResp.Header.Get("Cache-Control"))
	}
	var bundleBuf bytes.Buffer
	_, _ = bundleBuf.ReadFrom(resResp.Body)
	resolvedLeaf, cp0, err := pgns.VerifyResolveBundle(bundleBuf.Bytes(), fqdn, zone, ws, uint64(now))
	if err != nil {
		t.Fatalf("VerifyResolveBundle: %v", err)
	}
	if resolvedLeaf.Seq != 1 || cp0.Epoch != 0 {
		t.Fatalf("unexpected resolved state: seq=%d epoch=%d", resolvedLeaf.Seq, cp0.Epoch)
	}

	// Heartbeat 0-tx epoch 1 advances checkpoint epoch without mutating leaf.
	now += 60
	if err := seq.SealEpoch(context.Background()); err != nil {
		t.Fatalf("SealEpoch(1 heartbeat): %v", err)
	}
	if _, ep, ok := seq.LatestCheckpoint(); !ok || ep != 1 {
		t.Fatalf("expected latest epoch 1, got ok=%v ep=%d", ok, ep)
	}

	// Verify C2SP tile endpoint serves epoch 0..1 partial tile cleanly.
	tileResp, err := http.Get(seqSrv.URL + "/tiles/" + tlog.Tile{H: TileHeight, L: 0, N: 0, W: 2}.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer tileResp.Body.Close()
	if tileResp.StatusCode != http.StatusOK {
		t.Fatalf("GET tile status=%d", tileResp.StatusCode)
	}
	var tileBuf bytes.Buffer
	_, _ = tileBuf.ReadFrom(tileResp.Body)
	if tileBuf.Len() != 2*tlog.HashSize {
		t.Fatalf("tile data len=%d, want %d", tileBuf.Len(), 2*tlog.HashSize)
	}

	// Per-FQDN Update rate limit: 6 allowed in 60s, 7th returns 429 Too Many Requests.
	for i := range maxUpdatesPerMinute + 1 {
		upd := leaf1
		upd.Seq = 2
		upd.IssuedAt = uint64(now)
		upd.ExpiresAt = uint64(now + 3600)
		upd.Endpoints[0].Priority = uint16(10 + i)
		tx := pgns.LeafTx{TxType: pgns.TxTypeUpdate, Leaf: upd}
		_ = tx.SignOwner(owner)
		wire, _ := tx.MarshalCanonical()
		r, err := http.Post(seqSrv.URL+"/v1/submit", "application/octet-stream", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if i < maxUpdatesPerMinute && r.StatusCode != http.StatusAccepted {
			t.Fatalf("update %d status=%d, want 202", i, r.StatusCode)
		}
		if i == maxUpdatesPerMinute && r.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("7th update status=%d, want 429", r.StatusCode)
		}
	}
}
