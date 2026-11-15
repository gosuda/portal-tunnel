package portal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
)

type testPGNSWitness struct {
	key  pgns.WitnessKey
	priv ed25519.PrivateKey
}

func newTestPGNSWitnesses(t *testing.T, count int) ([]testPGNSWitness, pgns.WitnessSet) {
	t.Helper()
	out := make([]testPGNSWitness, count)
	keys := make([]pgns.WitnessKey, count)
	for i := range count {
		seed := sha256.Sum256([]byte{byte('w'), byte(i + 1)})
		priv := ed25519.NewKeyFromSeed(seed[:])
		pub := priv.Public().(ed25519.PublicKey)
		wk := pgns.WitnessKey{
			Name:      "w" + string(rune('1'+i)),
			PublicKey: pub,
		}
		out[i] = testPGNSWitness{key: wk, priv: priv}
		keys[i] = wk
	}
	ws := pgns.WitnessSet{
		Threshold: min(2, count),
		Witnesses: keys,
	}
	return out, ws
}

func privKeyFromIdentity(t *testing.T, id types.Identity) (*secp256k1.PrivateKey, [33]byte) {
	t.Helper()
	raw, err := hex.DecodeString(id.PrivateKey)
	if err != nil {
		t.Fatalf("decode identity private key: %v", err)
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	var pub33 [33]byte
	copy(pub33[:], priv.PubKey().SerializeCompressed())
	return priv, pub33
}

func makeTestPGNSLeaf(t *testing.T, fqdn string, priv *secp256k1.PrivateKey, seq uint64, issuedAt, expiresAt uint64, recoveryHash [32]byte) pgns.PortalLeafRecord {
	t.Helper()
	var pub33 [33]byte
	copy(pub33[:], priv.PubKey().SerializeCompressed())
	return pgns.PortalLeafRecord{
		Version:         pgns.LeafVersion,
		Flags:           pgns.FlagHTTP2,
		FQDN:            fqdn,
		Seq:             seq,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		OwnerPubKey:     pub33,
		RecoveryKeyHash: recoveryHash,
		TLSSPKISHA256:   sha256.Sum256([]byte("spki:" + fqdn)),
		ACMECAIssuer:    "letsencrypt.org",
		ACMEAccountURI:  "https://acme-v02.api.letsencrypt.org/acme/acct/1",
		Endpoints: []pgns.Endpoint{
			{
				RelayID:  [20]byte{0x01},
				IPv4:     [4]byte{93, 184, 216, 34},
				Port:     443,
				Priority: 10,
			},
		},
	}
}

func buildWitnessedPGNSProof(t *testing.T, zone string, leaf pgns.PortalLeafRecord, cpTime uint64, witnesses []testPGNSWitness) *types.PGNSRegistrationProof {
	t.Helper()
	rawLeaf, err := leaf.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	smt := pgns.NewSparseMerkleTree()
	smt.Put(pgns.SMTKey(leaf.FQDN), rawLeaf)
	proof, err := smt.Prove(pgns.SMTKey(leaf.FQDN))
	if err != nil {
		t.Fatalf("smt.Prove: %v", err)
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		t.Fatalf("proof.MarshalBinary: %v", err)
	}
	smtRoot := smt.Root()
	batchBytes, err := pgns.CanonicalBatchBytes([]pgns.LeafTx{{TxType: pgns.TxTypeCreate, Leaf: leaf}})
	if err != nil {
		t.Fatalf("CanonicalBatchBytes: %v", err)
	}
	recHash := pgns.EpochRecordHash(0, cpTime, smtRoot, batchBytes)
	logRoot, _, err := pgns.ComputeAppendLogRoot(0, recHash, nil)
	if err != nil {
		t.Fatalf("ComputeAppendLogRoot: %v", err)
	}
	body := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + zone,
		LogSize:   1,
		LogRoot:   logRoot,
		Epoch:     0,
		Timestamp: cpTime,
		SMTRoot:   smtRoot,
	}.FormatBody()
	cosigs := make([]pgns.WitnessCosignature, 0, len(witnesses))
	for _, w := range witnesses {
		c, err := pgns.CosignCheckpoint(body, w.key, w.priv, cpTime)
		if err != nil {
			t.Fatalf("CosignCheckpoint: %v", err)
		}
		cosigs = append(cosigs, c)
	}
	return &types.PGNSRegistrationProof{
		Zone:           zone,
		Leaf:           rawLeaf,
		InclusionProof: proofBytes,
		Checkpoint:     pgns.FormatSignedCheckpoint(body, cosigs),
	}
}

func registerPGNSThroughChallenge(t *testing.T, registry *leaseRegistry, id types.Identity, cacheOpt bool, proof *types.PGNSRegistrationProof) (*leaseRecord, *leaseRecord, types.RegisterResponse, error) {
	t.Helper()
	from := netip.MustParseAddr("203.0.113.50")
	req := types.RegisterChallengeRequest{
		Identity:  id,
		Namespace: types.LocalTLSNamespaceV1,
		Cache:     cacheOpt,
	}
	issued, err := registry.issueRegisterChallenge(req, "relay.example", "https://relay.example"+types.PathSDKRegister, from)
	if err != nil {
		return nil, nil, types.RegisterResponse{}, err
	}
	sig, err := identity.NewLocalAuthority(id).SignEthereumPersonalMessage(issued.SIWEMessage)
	if err != nil {
		t.Fatalf("SignEthereumPersonalMessage: %v", err)
	}
	challenge, sourceAddr, pgnsLeaf, err := registry.consumeVerifiedRegisterChallenge(types.RegisterRequest{
		ChallengeID:   issued.ChallengeID,
		SIWEMessage:   issued.SIWEMessage,
		SIWESignature: sig,
		PGNSProof:     proof,
	})
	if err != nil {
		return nil, nil, types.RegisterResponse{}, err
	}
	return registry.Register(challenge.Request, sourceAddr, "", types.RelayDescriptor{}, nil, nil, pgnsLeaf)
}

func assertAPIErrorCodeStatus(t *testing.T, err error, wantCode string, wantStatus int) {
	t.Helper()
	ae, ok := errors.AsType[*apiError](err)
	if !ok {
		t.Fatalf("error = %T (%v), want *apiError(%s)", err, err, wantCode)
	}
	if ae.code != wantCode || ae.status != wantStatus {
		t.Fatalf("apiError = (%s, %d, %s), want (%s, %d)", ae.code, ae.status, ae.msg, wantCode, wantStatus)
	}
}

func TestLeaseRegistryPGNSAdmissionAndWatermarks(t *testing.T) {
	t.Parallel()

	const zone = "portal.example"
	witnesses, witnessSet := newTestPGNSWitnesses(t, 3)
	registry := newTestRegistry(t, false, false)
	registry.pgnsWitnesses = witnessSet

	ownerID := newTestLeaseIdentity(t, "myapp")
	ownerPriv, _ := privKeyFromIdentity(t, ownerID)
	now := uint64(time.Now().UTC().Unix())

	appFQDN := "myapp.app." + zone
	leaf1 := makeTestPGNSLeaf(t, appFQDN, ownerPriv, 5, now-10, now+3600, [32]byte{})
	proof1 := buildWitnessedPGNSProof(t, zone, leaf1, now, witnesses)

	record, _, resp, err := registerPGNSThroughChallenge(t, registry, ownerID, false, proof1)
	if err != nil {
		t.Fatalf("witnessed PGNS registration failed: %v", err)
	}
	t.Cleanup(record.Close)

	if resp.Namespace != types.LocalTLSNamespaceV1 || resp.CanonicalHostname != appFQDN || resp.LegacyCanonicalHostname != "" {
		t.Fatalf("unexpected RegisterResponse: %+v", resp)
	}
	if registry.cache.Has(appFQDN) {
		t.Fatal("PGNS lease must never be registered in relay static cache")
	}
	if looked, ok := registry.Lookup(appFQDN); !ok || looked != record {
		t.Fatalf("Lookup(%q) = (%v, %v), want (%v, true)", appFQDN, looked, ok, record)
	}

	// Proof-less *.id registration succeeds when id-tag matches owner pubkey.
	idOwner := newTestLeaseIdentity(t, "web")
	idPriv, idPub33 := privKeyFromIdentity(t, idOwner)
	idTag, err := pgns.DeriveIDTag(idPub33)
	if err != nil {
		t.Fatalf("DeriveIDTag: %v", err)
	}
	idFQDN := "web." + idTag + ".id." + zone
	idLeaf := makeTestPGNSLeaf(t, idFQDN, idPriv, 1, now-10, now+3600, [32]byte{})
	rawIDLeaf, err := idLeaf.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical idLeaf: %v", err)
	}
	idRecord, _, _, err := registerPGNSThroughChallenge(t, registry, idOwner, false, &types.PGNSRegistrationProof{
		Zone: zone,
		Leaf: rawIDLeaf,
	})
	if err != nil {
		t.Fatalf("proof-less .id registration failed: %v", err)
	}
	t.Cleanup(idRecord.Close)
	if looked, ok := registry.Lookup(idFQDN); !ok || looked != idRecord {
		t.Fatalf("Lookup(%q) failed", idFQDN)
	}

	// Reject proof-less *.id registration when relay has PGNS disabled (empty WitnessSet).
	disabledRegistry := newTestRegistry(t, false, false)
	if _, _, _, err := registerPGNSThroughChallenge(t, disabledRegistry, idOwner, false, &types.PGNSRegistrationProof{
		Zone: zone,
		Leaf: rawIDLeaf,
	}); err == nil {
		t.Fatal("expected proof-less .id registration on PGNS-disabled relay to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Reject proof-less *.id registration when leaf.IssuedAt exceeds RelayCheckpointMaxLead (+60s).
	futureIDLeaf := makeTestPGNSLeaf(t, idFQDN, idPriv, 2, now+pgns.RelayCheckpointMaxLead+15, now+3600, [32]byte{})
	rawFutureIDLeaf, err := futureIDLeaf.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical futureIDLeaf: %v", err)
	}
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, idOwner, false, &types.PGNSRegistrationProof{
		Zone: zone,
		Leaf: rawFutureIDLeaf,
	}); err == nil {
		t.Fatal("expected future-dated proof-less .id leaf to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Reject cache opt-in on PGNS registration.
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, true, proof1); err == nil {
		t.Fatal("expected PGNS with cache=true to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusBadRequest)
	}

	// Reject proof-less *.app registration.
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, false, &types.PGNSRegistrationProof{
		Zone: zone,
		Leaf: proof1.Leaf,
	}); err == nil {
		t.Fatal("expected proof-less .app registration to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Reject SIWE signer mismatch.
	otherID := newTestLeaseIdentity(t, "myapp")
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, otherID, false, proof1); err == nil {
		t.Fatal("expected SIWE signer mismatch to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Reject insufficient witnesses (threshold=2, give 1).
	badWitnessProof := buildWitnessedPGNSProof(t, zone, leaf1, now, witnesses[:1])
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, false, badWitnessProof); err == nil {
		t.Fatal("expected insufficient witness quorum to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Reject stale checkpoint (> 600s old).
	staleCPProof := buildWitnessedPGNSProof(t, zone, leaf1, now-700, witnesses)
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, false, staleCPProof); err == nil {
		t.Fatal("expected stale checkpoint timestamp to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSProofInvalid, http.StatusForbidden)
	}

	// Watermark fencing persists across Unregister and janitor sweep.
	if _, err := registry.Unregister(types.UnregisterRequest{AccessToken: resp.AccessToken}); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if _, ok := registry.Lookup(appFQDN); ok {
		t.Fatal("unregistered PGNS lease must not resolve")
	}
	registry.cleanupExpired(time.Now().UTC().Add(100 * time.Second))

	staleSeqLeaf := makeTestPGNSLeaf(t, appFQDN, ownerPriv, 4, now-10, now+3600, [32]byte{})
	staleSeqProof := buildWitnessedPGNSProof(t, zone, staleSeqLeaf, now, witnesses)
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, false, staleSeqProof); err == nil {
		t.Fatal("expected seq below retained watermark to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSWatermarkStale, http.StatusConflict)
	}

	// Same seq with a different key is also stale while watermark holds.
	otherPriv, _ := privKeyFromIdentity(t, otherID)
	diffKeySameSeq := makeTestPGNSLeaf(t, appFQDN, otherPriv, 5, now-10, now+3600, [32]byte{})
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, otherID, false, buildWitnessedPGNSProof(t, zone, diffKeySameSeq, now, witnesses)); err == nil {
		t.Fatal("expected same seq from different key to fail")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSWatermarkStale, http.StatusConflict)
	}

	// Janitor prunes watermark once retainUntil has elapsed and no live record owns the FQDN.
	registry.cleanupExpired(time.Unix(int64(leaf1.ExpiresAt), 0).UTC().Add(time.Hour))
	registry.mu.RLock()
	_, exists := registry.pgnsWatermarks[appFQDN]
	registry.mu.RUnlock()
	if exists {
		t.Fatal("expected expired watermark with no live lease to be pruned")
	}
}

func TestLeaseRegistryPGNSColdRecoveryPreemption(t *testing.T) {
	t.Parallel()

	const zone = "portal.example"
	witnesses, witnessSet := newTestPGNSWitnesses(t, 3)
	registry := newTestRegistry(t, false, false)
	registry.pgnsWitnesses = witnessSet

	hotID := newTestLeaseIdentity(t, "myapp")
	hotPriv, _ := privKeyFromIdentity(t, hotID)
	recoveryID := newTestLeaseIdentity(t, "cold")
	_, recPub33 := privKeyFromIdentity(t, recoveryID)
	recHash, err := pgns.RecoveryKeyHash(recPub33)
	if err != nil {
		t.Fatalf("RecoveryKeyHash: %v", err)
	}
	now := uint64(time.Now().UTC().Unix())

	appFQDN := "myapp.app." + zone
	hotLeaf := makeTestPGNSLeaf(t, appFQDN, hotPriv, 1, now-10, now+3600, recHash)
	hotProof := buildWitnessedPGNSProof(t, zone, hotLeaf, now, witnesses)

	hotRecord, _, _, err := registerPGNSThroughChallenge(t, registry, hotID, false, hotProof)
	if err != nil {
		t.Fatalf("hot registration failed: %v", err)
	}

	// Recovery key rotates to a new hot identity at seq = 100.
	newHotID := newTestLeaseIdentity(t, "myapp")
	newHotPriv, newHotPub33 := privKeyFromIdentity(t, newHotID)
	recoveredLeaf := makeTestPGNSLeaf(t, appFQDN, newHotPriv, 100, now-5, now+7200, recHash)
	recoveredProof := buildWitnessedPGNSProof(t, zone, recoveredLeaf, now, witnesses)

	newRecord, _, _, err := registerPGNSThroughChallenge(t, registry, newHotID, false, recoveredProof)
	if err != nil {
		t.Fatalf("ColdRecovery preemption failed: %v", err)
	}
	t.Cleanup(newRecord.Close)

	// Old lease was closed and detached.
	hotRecord.mu.Lock()
	wasClosed := hotRecord.closed
	hotRecord.mu.Unlock()
	if !wasClosed {
		t.Fatal("expected superseded hot-key lease to be closed on ColdRecovery preemption")
	}
	if got, ok := registry.Lookup(appFQDN); !ok || got != newRecord {
		t.Fatalf("Lookup(%q) = (%v, %v), want new record %v", appFQDN, got, ok, newRecord)
	}
	if wm := registry.pgnsWatermarks[appFQDN]; wm.seq != 100 || wm.ownerPubKey != newHotPub33 {
		t.Fatalf("unexpected watermark after preemption: %+v", wm)
	}

	// Superseded hot key reconnecting with lower seq=2 is fenced with 409 pgns_watermark_stale.
	stolenLeaf := makeTestPGNSLeaf(t, appFQDN, hotPriv, 2, now-5, now+3600, recHash)
	stolenProof := buildWitnessedPGNSProof(t, zone, stolenLeaf, now, witnesses)
	if _, _, _, err := registerPGNSThroughChallenge(t, registry, hotID, false, stolenProof); err == nil {
		t.Fatal("expected compromised hot key at seq=2 to fail against seq=100 lease")
	} else {
		assertAPIErrorCodeStatus(t, err, types.APIErrorCodePGNSWatermarkStale, http.StatusConflict)
	}
}

func TestBridgeLeaseConnPGNSLocalTLSStart(t *testing.T) {
	t.Parallel()

	const zone = "portal.example"
	witnesses, witnessSet := newTestPGNSWitnesses(t, 2)
	registry := newTestRegistry(t, false, false)
	registry.pgnsWitnesses = witnessSet

	ownerID := newTestLeaseIdentity(t, "myapp")
	ownerPriv, _ := privKeyFromIdentity(t, ownerID)
	now := uint64(time.Now().UTC().Unix())
	appFQDN := "myapp.app." + zone
	leaf := makeTestPGNSLeaf(t, appFQDN, ownerPriv, 1, now-10, now+3600, [32]byte{})
	proof := buildWitnessedPGNSProof(t, zone, leaf, now, witnesses)

	record, _, _, err := registerPGNSThroughChallenge(t, registry, ownerID, false, proof)
	if err != nil {
		t.Fatalf("register PGNS lease: %v", err)
	}
	t.Cleanup(record.Close)
	registry.setIdentityAccess(record.ServiceKey(), types.LeaseRoutable, 1)

	reverseTunnelSide, reverseRelaySide := net.Pipe()
	defer func() {
		_ = reverseTunnelSide.Close()
		_ = reverseRelaySide.Close()
	}()
	if err := record.reverse.Offer(reverseRelaySide); err != nil {
		t.Fatalf("Offer reverse stream: %v", err)
	}

	clientSide, ingressRelaySide := net.Pipe()
	defer func() {
		_ = clientSide.Close()
		_ = ingressRelaySide.Close()
	}()

	srv := &Server{registry: registry}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	bridgeDone := make(chan error, 1)
	go func() {
		bridgeDone <- srv.bridgeLeaseConn(ctx, ingressRelaySide, record, []byte("client-hello-ignored"), true)
	}()

	mode, binding, err := transport.ReadStartMode(ctx, reverseTunnelSide, time.Second)
	if err != nil {
		t.Fatalf("ReadStartMode: %v", err)
	}
	if mode != transport.ReverseStartLocalTLS || len(binding) != 0 {
		t.Fatalf("start mode = (%v, len=%d), want (ReverseStartLocalTLS, 0)", mode, len(binding))
	}

	wantPayload := []byte("tls-ciphertext-passthrough")
	go func() {
		_, _ = clientSide.Write(wantPayload)
		_ = clientSide.Close()
	}()

	got, err := io.ReadAll(reverseTunnelSide)
	if err != nil {
		t.Fatalf("ReadAll reverseTunnelSide: %v", err)
	}
	if !bytes.Equal(got, wantPayload) {
		t.Fatalf("relayed bytes = %q, want %q", got, wantPayload)
	}
	_ = reverseTunnelSide.Close()

	if err := <-bridgeDone; err != nil {
		t.Fatalf("bridgeLeaseConn: %v", err)
	}
}
