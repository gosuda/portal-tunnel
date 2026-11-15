package dns

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/miekg/dns"
	"golang.org/x/mod/sumdb/tlog"

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

type epochBuilder struct {
	zone      string
	smt       *pgns.SparseMerkleTree
	logHashes []tlog.Hash
	prevLog   [32]byte
	wKey      pgns.WitnessKey
	wPriv     ed25519.PrivateKey
}

func newEpochBuilder(zone string, wKey pgns.WitnessKey, wPriv ed25519.PrivateKey) *epochBuilder {
	return &epochBuilder{
		zone:  zone,
		smt:   pgns.NewSparseMerkleTree(),
		wKey:  wKey,
		wPriv: wPriv,
	}
}

func (eb *epochBuilder) readHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		out[i] = eb.logHashes[idx]
	}
	return out, nil
}

func (eb *epochBuilder) buildEpoch(t *testing.T, epoch, ts uint64, txs []pgns.LeafTx) ([]byte, []byte, pgns.BatchTransitionProof) {
	t.Helper()
	prevSMTRoot := eb.smt.Root()
	keys := make([][32]byte, len(txs))
	for i, tx := range txs {
		keys[i] = pgns.SMTKey(tx.Leaf.FQDN)
	}
	prevLeaves, mp, err := eb.smt.ProvePreStateBatch(keys)
	if err != nil {
		t.Fatalf("ProvePreStateBatch: %v", err)
	}
	for _, tx := range txs {
		raw, err := tx.Leaf.MarshalCanonical()
		if err != nil {
			t.Fatalf("MarshalCanonical: %v", err)
		}
		eb.smt.Put(pgns.SMTKey(tx.Leaf.FQDN), raw)
	}
	batchBytes, err := pgns.CanonicalBatchBytes(txs)
	if err != nil {
		t.Fatalf("CanonicalBatchBytes: %v", err)
	}
	recHash := pgns.EpochRecordHash(epoch, ts, eb.smt.Root(), batchBytes)
	hr := tlog.HashReaderFunc(eb.readHashes)
	logRoot, added, err := pgns.ComputeAppendLogRoot(epoch, recHash, hr)
	if err != nil {
		t.Fatalf("ComputeAppendLogRoot: %v", err)
	}
	eb.logHashes = append(eb.logHashes, added...)
	var cons tlog.TreeProof
	var recP tlog.RecordProof
	if epoch > 0 {
		cons, err = tlog.ProveTree(int64(epoch+1), int64(epoch), hr)
		if err != nil {
			t.Fatalf("ProveTree: %v", err)
		}
		recP, err = tlog.ProveRecord(int64(epoch+1), int64(epoch), hr)
		if err != nil {
			t.Fatalf("ProveRecord: %v", err)
		}
	}
	batch := pgns.BatchTransitionProof{
		Zone:              eb.zone,
		Epoch:             epoch,
		Timestamp:         ts,
		PrevLogRoot:       eb.prevLog,
		NewLogRoot:        logRoot,
		PrevSMTRoot:       prevSMTRoot,
		NewSMTRoot:        eb.smt.Root(),
		TxEntries:         txs,
		PrevLeaves:        prevLeaves,
		PreStateMP:        mp,
		ConsistencyProof:  cons,
		AppendRecordProof: recP,
	}
	eb.prevLog = logRoot
	rawBatch, err := batch.MarshalBinary()
	if err != nil {
		t.Fatalf("batch.MarshalBinary: %v", err)
	}
	body := pgns.Checkpoint{
		Origin:    pgns.CheckpointOriginPrefix + eb.zone,
		LogSize:   epoch + 1,
		LogRoot:   logRoot,
		Epoch:     epoch,
		Timestamp: ts,
		SMTRoot:   eb.smt.Root(),
	}.FormatBody()
	cosig, err := pgns.CosignCheckpoint(body, eb.wKey, eb.wPriv, ts)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %v", err)
	}
	rawCP := pgns.FormatSignedCheckpoint(body, []pgns.WitnessCosignature{cosig})
	return rawCP, rawBatch, batch
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

	eb := newEpochBuilder(zone, wKey, wPriv)
	rawLeaf, err := leaf.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	createTx := pgns.LeafTx{
		TxType:   pgns.TxTypeCreate,
		Leaf:     leaf,
		PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, rawLeaf, pgns.PoWDifficultyID),
	}
	if err := createTx.SignOwner(owner); err != nil {
		t.Fatal(err)
	}
	rawCP, rawBatch, batch0 := eb.buildEpoch(t, 0, te, []pgns.LeafTx{createTx})

	// Reject NameserverGlue overlapping tenant namespace.
	if _, err := New(Config{
		Zone:        zone,
		WitnessSet:  ws,
		Keys:        keys,
		Nameservers: []NameserverGlue{{Host: "ns1.app." + zone, IPv4: net.IPv4(1, 1, 1, 1)}},
	}); !errors.Is(err, pgns.ErrInvalidFQDN) {
		t.Fatalf("expected overlapping NameserverGlue to fail with ErrInvalidFQDN, got %v", err)
	}

	srv1, err := New(Config{Zone: zone, WitnessSet: ws, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	srv2, err := New(Config{Zone: zone, WitnessSet: ws, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}

	// Forged batch with tampered TxEntries MUST be rejected without mutating server state.
	forgedBatch := batch0
	forgedBatch.TxEntries = nil
	forgedBatch.PrevLeaves = nil
	rawForged, _ := forgedBatch.MarshalBinary()
	if err := srv1.ApplyEpoch(rawCP, rawForged); err == nil {
		t.Fatal("expected ApplyEpoch to reject forged batch TxEntries")
	}

	if err := srv1.ApplyEpoch(rawCP, rawBatch); err != nil {
		t.Fatalf("srv1 ApplyEpoch: %v", err)
	}
	if err := srv2.ApplyEpoch(rawCP, rawBatch); err != nil {
		t.Fatalf("srv2 ApplyEpoch: %v", err)
	}

	// 1. Primary-only A record, clamped TTL (expires_at - T_e = 20 <= 30), valid RRSIG identical across signers, OPT echoed.
	a1 := queryDNS(srv1, fqdn, dns.TypeA, true)
	a2 := queryDNS(srv2, fqdn, dns.TypeA, true)
	if a1.Rcode != dns.RcodeSuccess || len(a1.Answer) != 2 {
		t.Fatalf("unexpected A answer: rcode=%d answers=%v", a1.Rcode, a1.Answer)
	}
	if a1.IsEdns0() == nil {
		t.Fatal("expected EDNS0 OPT pseudo-RR echoed in Extra")
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

	// EDNS0 Version=1 MUST return BADVERS per RFC 6891.
	badEdnsReq := new(dns.Msg)
	badEdnsReq.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	opt.SetVersion(1)
	badEdnsReq.Extra = append(badEdnsReq.Extra, opt)
	rwBad := &recorderWriter{}
	srv1.ServeDNS(rwBad, badEdnsReq)
	if rwBad.msg == nil || rwBad.msg.Rcode != dns.RcodeBadVers {
		t.Fatalf("EDNS0 version 1 rcode = %v, want RcodeBadVers", rwBad.msg)
	}

	// QTYPE=RRSIG returns owner RRSIG records directly.
	rrsigMsg := queryDNS(srv1, fqdn, dns.TypeRRSIG, false)
	if rrsigMsg.Rcode != dns.RcodeSuccess || len(rrsigMsg.Answer) == 0 {
		t.Fatalf("expected QTYPE=RRSIG to return owner RRSIGs, got rcode=%d answers=%d", rrsigMsg.Rcode, len(rrsigMsg.Answer))
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

	// 5. Empty Non-Terminal (<id-tag>.id.<zone>): DO=1 includes empty-bitmap NSEC3; DO=0 omits NSEC3!
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
		t.Fatal("missing ENT NSEC3 in DO=1 NOERROR NODATA response")
	}
	entNoDO := queryDNS(srv1, tag+".id."+zone, dns.TypeA, false)
	for _, rr := range entNoDO.Ns {
		if _, ok := rr.(*dns.NSEC3); ok {
			t.Fatal("DO=0 NODATA response must not include NSEC3 records")
		}
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

// INV: Unchanged leaf RRsets and NSEC3 records retain their cached RRSIG across 0-tx
// heartbeat epochs while remaining signature validity exceeds RRSIGRefreshThreshold (6h),
// and refresh deterministically on their staggered bucket epoch once remaining <= 6h.
func TestStaggeredRRSIGBucketRefreshAvoidsEagerReSigning(t *testing.T) {
	const zone = "portal.example"
	t0 := uint64(1_700_000_000)

	keys, err := GenerateStage1Keys(zone, uint32(t0-300), uint32(t0+7*86400))
	if err != nil {
		t.Fatal(err)
	}
	wSeed := sha256.Sum256([]byte("dns-stagger-witness"))
	wPriv := ed25519.NewKeyFromSeed(wSeed[:])
	wKey := pgns.WitnessKey{Name: "w1", PublicKey: wPriv.Public().(ed25519.PublicKey)}
	ws := pgns.WitnessSet{Threshold: 1, Witnesses: []pgns.WitnessKey{wKey}}

	oSeed := sha256.Sum256([]byte("dns-stagger-owner"))
	owner := secp256k1.PrivKeyFromBytes(oSeed[:])
	var pub33 [33]byte
	copy(pub33[:], owner.PubKey().SerializeCompressed())
	tag, _ := pgns.DeriveIDTag(pub33)
	fqdn := "web." + tag + ".id." + zone

	leaf := pgns.PortalLeafRecord{
		Version:       pgns.LeafVersion,
		Flags:         pgns.FlagHTTP2,
		FQDN:          fqdn,
		Seq:           1,
		IssuedAt:      t0,
		ExpiresAt:     t0 + 48*3600,
		OwnerPubKey:   pub33,
		TLSSPKISHA256: sha256.Sum256([]byte("spki-stagger")),
		Endpoints: []pgns.Endpoint{
			{RelayID: [20]byte{1}, IPv4: [4]byte{93, 184, 216, 34}, Port: 443, Priority: 10},
		},
	}
	rawLeaf, _ := leaf.MarshalCanonical()
	createTx := pgns.LeafTx{
		TxType:   pgns.TxTypeCreate,
		Leaf:     leaf,
		PoWNonce: pgns.MinePoW(pgns.TxTypeCreate, rawLeaf, pgns.PoWDifficultyID),
	}
	_ = createTx.SignOwner(owner)

	eb := newEpochBuilder(zone, wKey, wPriv)
	srv, err := New(Config{Zone: zone, WitnessSet: ws, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}

	cp0, batch0, _ := eb.buildEpoch(t, 0, t0, []pgns.LeafTx{createTx})
	if err := srv.ApplyEpoch(cp0, batch0); err != nil {
		t.Fatalf("ApplyEpoch(0): %v", err)
	}
	initialSig := queryDNS(srv, fqdn, dns.TypeA, true).Answer[1].(*dns.RRSIG)

	// Across epochs 1..24 at +60s spacing, remaining RRSIG validity (~24h) >> 6h threshold:
	// cached signature MUST NOT be regenerated on any bucket epoch!
	ts := t0
	for ep := uint64(1); ep <= DefaultRefreshBuckets; ep++ {
		ts += 60
		cp, b, _ := eb.buildEpoch(t, ep, ts, nil)
		if err := srv.ApplyEpoch(cp, b); err != nil {
			t.Fatalf("ApplyEpoch(%d): %v", ep, err)
		}
	}
	after24Sig := queryDNS(srv, fqdn, dns.TypeA, true).Answer[1].(*dns.RRSIG)
	if after24Sig.Expiration != initialSig.Expiration || after24Sig.Signature != initialSig.Signature {
		t.Fatalf("RRSIG eagerly re-signed when remaining validity > 6h: initial exp=%d after24 exp=%d", initialSig.Expiration, after24Sig.Expiration)
	}

	// Advance timestamp into the <= 6h refresh window (initial Expiration - RRSIGRefreshThreshold + 60)
	// and step up to DefaultRefreshBuckets epochs so the leaf's bucket epoch fires and refreshes RRSIG.
	ts = uint64(initialSig.Expiration) - RRSIGRefreshThreshold + 60
	for step := uint64(1); step <= DefaultRefreshBuckets; step++ {
		ep := DefaultRefreshBuckets + step
		cp, b, _ := eb.buildEpoch(t, ep, ts, nil)
		if err := srv.ApplyEpoch(cp, b); err != nil {
			t.Fatalf("ApplyEpoch(%d): %v", ep, err)
		}
		ts += 60
	}
	refreshedSig := queryDNS(srv, fqdn, dns.TypeA, true).Answer[1].(*dns.RRSIG)
	if refreshedSig.Expiration <= initialSig.Expiration {
		t.Fatalf("expected staggered RRSIG refresh once remaining <= 6h, got exp=%d <= initial=%d", refreshedSig.Expiration, initialSig.Expiration)
	}
}
