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
	logRoot, _, _ := pgns.ComputeAppendLogRoot(0, recHash, nil)
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
}
