package ctmonitor

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

func testLeafCert(t *testing.T, sans ...string) (*x509.Certificate, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		DNSNames:     sans,
		NotBefore:    time.Unix(1_699_999_900, 0),
		NotAfter:     time.Unix(1_700_005_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// INV: CheckCertificate permits active tls_spki_sha256 and next_tls_spki_sha256
// certs while flagging rogue SPKIs, unregistered FQDNs, and wildcard SANs.
func TestMonitorSPKIAudit(t *testing.T) {
	const zone = "portal.example"
	ts := uint64(1_700_000_000)

	wSeed := sha256.Sum256([]byte("ct-witness"))
	wPriv := ed25519.NewKeyFromSeed(wSeed[:])
	wKey := pgns.WitnessKey{Name: "w1", PublicKey: wPriv.Public().(ed25519.PublicKey)}
	ws := pgns.WitnessSet{Threshold: 1, Witnesses: []pgns.WitnessKey{wKey}}

	oSeed := sha256.Sum256([]byte("ct-owner"))
	owner := secp256k1.PrivKeyFromBytes(oSeed[:])
	var pub33 [33]byte
	copy(pub33[:], owner.PubKey().SerializeCompressed())
	tag, _ := pgns.DeriveIDTag(pub33)
	fqdn := "web." + tag + ".id." + zone

	activeCert, activeSPKI := testLeafCert(t, fqdn)
	stagedCert, stagedSPKI := testLeafCert(t, fqdn)
	rogueCert, _ := testLeafCert(t, fqdn)
	wildcardCert, _ := testLeafCert(t, "*."+fqdn)

	leaf := pgns.PortalLeafRecord{
		Version:           pgns.LeafVersion,
		Flags:             pgns.FlagHTTP2,
		FQDN:              fqdn,
		Seq:               1,
		IssuedAt:          ts,
		ExpiresAt:         ts + 3600,
		OwnerPubKey:       pub33,
		TLSSPKISHA256:     activeSPKI,
		NextTLSSPKISHA256: stagedSPKI,
		Endpoints: []pgns.Endpoint{{
			RelayID:  [20]byte{1},
			IPv4:     [4]byte{93, 184, 216, 34},
			Port:     443,
			Priority: 10,
		}},
	}
	rawLeaf, _ := leaf.MarshalCanonical()
	tx := pgns.LeafTx{TxType: pgns.TxTypeCreate, Leaf: leaf, PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, rawLeaf, pgns.PoWDifficultyID)}
	_ = tx.SignOwner(owner)

	smt := pgns.NewSparseMerkleTree()
	prevLeaves, mp, _ := smt.ProvePreStateBatch([][32]byte{pgns.SMTKey(fqdn)})
	smt.Put(pgns.SMTKey(fqdn), rawLeaf)
	batchBytes, _ := pgns.CanonicalBatchBytes([]pgns.LeafTx{tx})
	recHash := pgns.EpochRecordHash(0, ts, smt.Root(), batchBytes)
	logRoot, added0, _ := pgns.ComputeAppendLogRoot(0, recHash, nil)
	batch := pgns.BatchTransitionProof{
		Zone:        zone,
		Epoch:       0,
		Timestamp:   ts,
		PrevSMTRoot: pgns.EmptySubtree[0],
		NewSMTRoot:  smt.Root(),
		NewLogRoot:  logRoot,
		TxEntries:   []pgns.LeafTx{tx},
		PrevLeaves:  prevLeaves,
		PreStateMP:  mp,
	}
	rawBatch, _ := batch.MarshalBinary()
	cpBody := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + zone,
		LogSize:   1,
		LogRoot:   logRoot,
		Epoch:     0,
		Timestamp: ts,
		SMTRoot:   smt.Root(),
	}.FormatBody()
	cosig, _ := pgns.CosignCheckpoint(cpBody, wKey, wPriv, ts)
	rawCP := pgns.FormatSignedCheckpoint(cpBody, []pgns.WitnessCosignature{cosig})

	mon, err := New(zone, ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := mon.ApplyEpoch(rawCP, rawBatch); err != nil {
		t.Fatalf("ApplyEpoch: %v", err)
	}

	if err := mon.CheckCertificate(activeCert); err != nil {
		t.Fatalf("active cert rejected: %v", err)
	}
	if err := mon.CheckCertificate(stagedCert); err != nil {
		t.Fatalf("staged next_tls_spki_sha256 cert rejected: %v", err)
	}
	if err := mon.CheckCertificate(rogueCert); !errors.Is(err, ErrUnauthorizedCertificate) {
		t.Fatalf("rogue cert got %v, want %v", err, ErrUnauthorizedCertificate)
	}
	if err := mon.CheckCertificate(wildcardCert); !errors.Is(err, ErrUnauthorizedCertificate) {
		t.Fatalf("wildcard cert got %v, want %v", err, ErrUnauthorizedCertificate)
	}

	// Forged batch with tampered TxEntries (dropped tx while keeping NewSMTRoot) MUST fail ApplyEpoch.
	forgedBatch := batch
	forgedBatch.TxEntries = nil
	forgedBatch.PrevLeaves = nil
	rawForgedBatch, _ := forgedBatch.MarshalBinary()
	mon2, err := New(zone, ws)
	if err != nil {
		t.Fatal(err)
	}
	if err := mon2.ApplyEpoch(rawCP, rawForgedBatch); err == nil {
		t.Fatal("expected ApplyEpoch to reject forged batch TxEntries")
	}

	// Advancing to an epoch past leaf.ExpiresAt MUST prune the expired leaf so CheckCertificate rejects it.
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = added0[idx]
		}
		return out, nil
	})
	ts1 := leaf.ExpiresAt
	emptyBatchBytes, _ := pgns.CanonicalBatchBytes(nil)
	recHash1 := pgns.EpochRecordHash(1, ts1, smt.Root(), emptyBatchBytes)
	logRoot1, added1, err := pgns.ComputeAppendLogRoot(1, recHash1, hr)
	if err != nil {
		t.Fatal(err)
	}
	allHashes := append(append([]tlog.Hash(nil), added0...), added1...)
	hrFull := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = allHashes[idx]
		}
		return out, nil
	})
	cons1, _ := tlog.ProveTree(2, 1, hrFull)
	recP1, _ := tlog.ProveRecord(2, 1, hrFull)
	batch1 := pgns.BatchTransitionProof{
		Zone:              zone,
		Epoch:             1,
		Timestamp:         ts1,
		PrevLogRoot:       logRoot,
		NewLogRoot:        logRoot1,
		PrevSMTRoot:       smt.Root(),
		NewSMTRoot:        smt.Root(),
		ConsistencyProof:  cons1,
		AppendRecordProof: recP1,
	}
	rawBatch1, _ := batch1.MarshalBinary()
	cpBody1 := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + zone,
		LogSize:   2,
		LogRoot:   logRoot1,
		Epoch:     1,
		Timestamp: ts1,
		SMTRoot:   smt.Root(),
	}.FormatBody()
	cosig1, _ := pgns.CosignCheckpoint(cpBody1, wKey, wPriv, ts1)
	rawCP1 := pgns.FormatSignedCheckpoint(cpBody1, []pgns.WitnessCosignature{cosig1})
	if err := mon.ApplyEpoch(rawCP1, rawBatch1); err != nil {
		t.Fatalf("ApplyEpoch(1 expired): %v", err)
	}
	if err := mon.CheckCertificate(activeCert); !errors.Is(err, ErrUnauthorizedCertificate) {
		t.Fatalf("expired leaf cert got %v, want %v", err, ErrUnauthorizedCertificate)
	}
}
