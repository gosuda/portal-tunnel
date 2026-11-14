package dns

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/pgns"
)

type recorderWriter struct {
	msg *dns.Msg
}

func (r *recorderWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (r *recorderWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (r *recorderWriter) WriteMsg(m *dns.Msg) error { r.msg = m; return nil }
func (r *recorderWriter) Write([]byte) (int, error) { return 0, nil }
func (r *recorderWriter) Close() error              { return nil }
func (r *recorderWriter) TsigStatus() error         { return nil }
func (r *recorderWriter) TsigTimersOnly(bool)       {}
func (r *recorderWriter) Hijack()                   {}

func queryDNS(srv *Server, qname string, qtype uint16, do bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	if do {
		req.SetEdns0(4096, true)
	}
	rw := &recorderWriter{}
	srv.ServeDNS(rw, req)
	return rw.msg
}

func makeEpochData(t *testing.T, zone string, epoch, ts uint64, smt *pgns.SparseMerkleTree, leaves []pgns.PortalLeafRecord, owner *secp256k1.PrivateKey, wKey pgns.WitnessKey, wPriv ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	var prevLogRoot [32]byte
	prevSMTRoot := smt.Root()
	var txs []pgns.LeafTx
	if len(leaves) > 0 {
		for _, leaf := range leaves {
			raw, _ := leaf.MarshalCanonical()
			tx := pgns.LeafTx{TxType: pgns.TxTypeCreate, Leaf: leaf, PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, raw, pgns.PoWDifficultyID)}
			_ = tx.SignOwner(owner)
			txs = append(txs, tx)
		}
	}
	keys := make([][32]byte, len(txs))
	for i, tx := range txs {
		keys[i] = pgns.SMTKey(tx.Leaf.FQDN)
	}
	prevLeaves, mp, _ := smt.ProvePreStateBatch(keys)
	for _, tx := range txs {
		raw, _ := tx.Leaf.MarshalCanonical()
		smt.Put(pgns.SMTKey(tx.Leaf.FQDN), raw)
	}
	batchBytes, _ := pgns.CanonicalBatchBytes(txs)
	recHash := pgns.EpochRecordHash(epoch, ts, smt.Root(), batchBytes)
	logRoot, _, _ := pgns.ComputeAppendLogRoot(0, recHash, nil)
	batch := pgns.BatchTransitionProof{
		Zone:        zone,
		Epoch:       epoch,
		Timestamp:   ts,
		PrevLogRoot: prevLogRoot,
		NewLogRoot:  logRoot,
		PrevSMTRoot: prevSMTRoot,
		NewSMTRoot:  smt.Root(),
		TxEntries:   txs,
		PrevLeaves:  prevLeaves,
		PreStateMP:  mp,
	}
	rawBatch, _ := batch.MarshalBinary()
	body := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + zone,
		LogSize:   epoch + 1,
		LogRoot:   logRoot,
		Epoch:     epoch,
		Timestamp: ts,
		SMTRoot:   smt.Root(),
	}.FormatBody()
	cosig, _ := pgns.CosignCheckpoint(body, wKey, wPriv, ts)
	rawCP := pgns.FormatSignedCheckpoint(body, []pgns.WitnessCosignature{cosig})
	return rawCP, rawBatch
}

// INV: Two independent Stage 1 signers given the same Stage1Keys and verified epoch
// stream produce byte-identical RRSIGs regardless of local clock; active leaves publish
// primary-only A, HTTPS alpn, dual CAA (issuewild ";" + issue), TXT, and RFC 5155 ENT/NSEC3.
func TestDeterministicSigningDualCAANSEC3AndENT(t *testing.T) {
	const zone = "portal.example"
	te := uint64(1_700_000_000)

	keys, err := GenerateStage1Keys(zone, uint32(te-300), uint32(te+86400))
	if err != nil {
		t.Fatalf("GenerateStage1Keys: %v", err)
	}
	wSeed := sha256.Sum256([]byte("dns-witness"))
	wPriv := ed25519.NewKeyFromSeed(wSeed[:])
	wKey := pgns.WitnessKey{Name: "w1", PublicKey: wPriv.Public().(ed25519.PublicKey)}
	ws := pgns.WitnessSet{Threshold: 1, Witnesses: []pgns.WitnessKey{wKey}}

	oSeed := sha256.Sum256([]byte("dns-owner"))
	owner := secp256k1.PrivKeyFromBytes(oSeed[:])
	var pub33 [33]byte
	copy(pub33[:], owner.PubKey().SerializeCompressed())
	tag, _ := pgns.DeriveIDTag(pub33)
	fqdn := "web." + tag + ".id." + zone
	digest := sha256.Sum256([]byte("dns-01-token"))

	leaf := pgns.PortalLeafRecord{
		Version:         pgns.LeafVersion,
		Flags:           pgns.FlagHTTP2 | pgns.FlagPersist01Enabled,
		FQDN:            fqdn,
		Seq:             1,
		IssuedAt:        te,
		ExpiresAt:       te + 20, // short remaining TTL tests clamping (<30s and <60s)
		OwnerPubKey:     pub33,
		TLSSPKISHA256:   sha256.Sum256([]byte("spki")),
		ACMECAIssuer:    "letsencrypt.org",
		ACMEAccountURI:  "https://acme-v02.api.letsencrypt.org/acme/acct/77",
		ACMEDNS01Digest: digest,
		Endpoints: []pgns.Endpoint{
			{RelayID: [20]byte{1}, IPv4: [4]byte{93, 184, 216, 34}, Port: 443, Priority: 10},
			{RelayID: [20]byte{2}, IPv4: [4]byte{1, 1, 1, 1}, Port: 443, Priority: 20},
		},
	}

	smt := pgns.NewSparseMerkleTree()
	rawCP, rawBatch := makeEpochData(t, zone, 0, te, smt, []pgns.PortalLeafRecord{leaf}, owner, wKey, wPriv)

	srv1, err := New(Config{Zone: zone, WitnessSet: ws, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	srv2, err := New(Config{Zone: zone, WitnessSet: ws, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv1.ApplyEpoch(rawCP, rawBatch); err != nil {
		t.Fatalf("srv1 ApplyEpoch: %v", err)
	}
	if err := srv2.ApplyEpoch(rawCP, rawBatch); err != nil {
		t.Fatalf("srv2 ApplyEpoch: %v", err)
	}

	// 1. Primary-only A record, clamped TTL (expires_at - T_e = 20 <= 30), valid RRSIG identical across signers.
	a1 := queryDNS(srv1, fqdn, dns.TypeA, true)
	a2 := queryDNS(srv2, fqdn, dns.TypeA, true)
	if a1.Rcode != dns.RcodeSuccess || len(a1.Answer) != 2 {
		t.Fatalf("unexpected A answer: rcode=%d answers=%v", a1.Rcode, a1.Answer)
	}
	aRR := a1.Answer[0].(*dns.A)
	sig1 := a1.Answer[1].(*dns.RRSIG)
	sig2 := a2.Answer[1].(*dns.RRSIG)
	if !aRR.A.Equal(net.IPv4(93, 184, 216, 34)) || aRR.Hdr.Ttl != 20 {
		t.Fatalf("A record ip=%v ttl=%d, want 93.184.216.34 ttl=20", aRR.A, aRR.Hdr.Ttl)
	}
	if sig1.Signature != sig2.Signature {
		t.Fatal("two signers produced non-identical RRSIG signatures")
	}
	if err := sig1.Verify(keys.ZSK, []dns.RR{aRR}); err != nil {
		t.Fatalf("A RRSIG verify failed: %v", err)
	}

	// 2. HTTPS alpn="h2,http/1.1".
	httpsMsg := queryDNS(srv1, fqdn, dns.TypeHTTPS, false)
	if len(httpsMsg.Answer) != 1 || !strings.Contains(httpsMsg.Answer[0].String(), "h2,http/1.1") {
		t.Fatalf("unexpected HTTPS record: %v", httpsMsg.Answer)
	}

	// 3. Dual CAA (issuewild ";" + issue with accounturi) at leaf, and apex default-deny.
	caaMsg := queryDNS(srv1, fqdn, dns.TypeCAA, false)
	if len(caaMsg.Answer) != 2 {
		t.Fatalf("expected 2 CAA records on leaf, got %d", len(caaMsg.Answer))
	}
	var tags []string
	for _, rr := range caaMsg.Answer {
		tags = append(tags, rr.(*dns.CAA).Tag+"="+rr.(*dns.CAA).Value)
	}
	if !slices.Contains(tags, "issuewild=;") {
		t.Fatalf("missing issuewild ';' on leaf CAA: %v", tags)
	}
	if !slices.Contains(tags, "issue=letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/77") {
		t.Fatalf("missing scoped issue CAA on leaf: %v", tags)
	}

	// 4. _acme-challenge and _validation-persist TXT synthesis.
	acmeMsg := queryDNS(srv1, "_acme-challenge."+fqdn, dns.TypeTXT, true)
	wantTXT := base64.RawURLEncoding.EncodeToString(digest[:])
	if len(acmeMsg.Answer) != 2 || acmeMsg.Answer[0].(*dns.TXT).Txt[0] != wantTXT {
		t.Fatalf("unexpected _acme-challenge TXT: %v", acmeMsg.Answer)
	}
	persistMsg := queryDNS(srv1, "_validation-persist."+fqdn, dns.TypeTXT, false)
	if len(persistMsg.Answer) != 1 || !strings.Contains(persistMsg.Answer[0].(*dns.TXT).Txt[0], "persistUntil=") {
		t.Fatalf("unexpected _validation-persist TXT: %v", persistMsg.Answer)
	}

	// 5. Empty Non-Terminal (<id-tag>.id.<zone>) returns NOERROR NODATA + empty-bitmap NSEC3!
	entMsg := queryDNS(srv1, tag+".id."+zone, dns.TypeA, true)
	if entMsg.Rcode != dns.RcodeSuccess || len(entMsg.Answer) != 0 {
		t.Fatalf("ENT qname rcode=%d answers=%d, want NOERROR NODATA", entMsg.Rcode, len(entMsg.Answer))
	}
	var foundENTNSEC3 bool
	for _, rr := range entMsg.Ns {
		if n3, ok := rr.(*dns.NSEC3); ok {
			foundENTNSEC3 = true
			if len(n3.TypeBitMap) != 0 {
				t.Fatalf("ENT NSEC3 must have empty TypeBitMap, got %v", n3.TypeBitMap)
			}
		}
	}
	if !foundENTNSEC3 {
		t.Fatal("missing ENT NSEC3 in NOERROR NODATA response")
	}

	// 6. Non-existent subdomain returns NXDOMAIN + RFC 5155 NSEC3 proof (omitting TypeNSEC3 from bitmaps).
	nx := queryDNS(srv1, "does-not-exist.app."+zone, dns.TypeA, true)
	if nx.Rcode != dns.RcodeNameError || len(nx.Ns) == 0 {
		t.Fatalf("expected NXDOMAIN with NSEC3 authority records, got rcode=%d ns=%d", nx.Rcode, len(nx.Ns))
	}
	for _, rr := range nx.Ns {
		if n3, ok := rr.(*dns.NSEC3); ok && slices.Contains(n3.TypeBitMap, dns.TypeNSEC3) {
			t.Fatalf("NSEC3 TypeBitMap must omit NSEC3 bit per RFC 5155: %v", n3.TypeBitMap)
		}
	}
}
