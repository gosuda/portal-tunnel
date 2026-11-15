package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	mdns "github.com/miekg/dns"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/pgns"
	pgnsdns "github.com/gosuda/portal-tunnel/v2/pgns/dns"
	"github.com/gosuda/portal-tunnel/v2/pgns/sequencer"
	"github.com/gosuda/portal-tunnel/v2/pgns/witness"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func startTestPGNSControlPlane(t *testing.T, zone string) (pgns.WitnessSet, []string, *sequencer.Sequencer, string, *pgnsdns.Server, string) {
	t.Helper()

	var ws pgns.WitnessSet
	ws.Threshold = 2
	var witnessSpecs, witnessURLs []string
	for _, name := range []string{"w1", "w2", "w3"} {
		seed := sha256.Sum256([]byte("e2e-pgns-witness:" + name))
		priv := ed25519.NewKeyFromSeed(seed[:])
		w, err := witness.New(witness.Config{Zone: zone, Name: name, PrivateKey: priv})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(w.Handler())
		t.Cleanup(srv.Close)
		ws.Witnesses = append(ws.Witnesses, w.Key())
		witnessSpecs = append(witnessSpecs, name+"="+hex.EncodeToString(w.Key().PublicKey))
		witnessURLs = append(witnessURLs, srv.URL)
	}

	seq, err := sequencer.New(sequencer.Config{
		Zone:              zone,
		WitnessSet:        ws,
		WitnessEndpoints:  witnessURLs,
		ActiveInterval:    30 * time.Millisecond,
		HeartbeatInterval: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	seqCtx, cancelSeq := context.WithCancel(context.Background())
	t.Cleanup(cancelSeq)
	go func() { _ = seq.Run(seqCtx) }()
	seqSrv := httptest.NewServer(seq.Handler())
	t.Cleanup(seqSrv.Close)

	nowSec := uint64(time.Now().UTC().Unix())
	keys, err := pgnsdns.GenerateStage1Keys(zone, uint32(nowSec-300), uint32(nowSec+24*3600))
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv, err := pgnsdns.New(pgnsdns.Config{
		Zone:       zone,
		WitnessSet: ws,
		Keys:       keys,
		Nameservers: []pgnsdns.NameserverGlue{{
			Host: "ns1." + zone,
			IPv4: net.IPv4(93, 184, 216, 53),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &mdns.Server{PacketConn: pc, Handler: dnsSrv}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })

	return ws, witnessSpecs, seq, seqSrv.URL, dnsSrv, pc.LocalAddr().String()
}

func startUntrustedRelay(t *testing.T, ctx context.Context, ws pgns.WitnessSet) (*portal.Server, string, string) {
	t.Helper()
	port := harnessPort(t, "127.0.0.1")
	sniAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	relay, err := portal.NewServer(portal.ServerConfig{
		TenantCertificates: false,
		PortalURL:          "https://" + sniAddr,
		StateDir:           t.TempDir(),
		SNIListenAddr:      sniAddr,
		SNIPort:            port,
		PGNSWitnesses:      ws,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, relayHandler(relay, nil)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = relay.Shutdown(shutdownCtx)
		_ = relay.Wait()
	})
	return relay, sniAddr, "https://" + sniAddr
}

func syncDNSEpoch(t *testing.T, seq *sequencer.Sequencer, dnsSrv *pgnsdns.Server, epoch uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		rawCP, latestEp, ok := seq.LatestCheckpoint()
		if ok && latestEp >= epoch {
			if latestEp != epoch {
				t.Fatalf("sequencer skipped epoch %d (at %d)", epoch, latestEp)
			}
			rawBatch, hasBatch := seq.Batch(epoch)
			if !hasBatch {
				t.Fatalf("missing batch for epoch %d", epoch)
			}
			if err := dnsSrv.ApplyEpoch(rawCP, rawBatch); err != nil {
				t.Fatalf("ApplyEpoch(%d): %v", epoch, err)
			}
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		<-tick.C
	}
	t.Fatalf("timed out waiting for sequencer epoch %d", epoch)
}

func queryDNS(t *testing.T, addr, name string, qtype uint16) *mdns.Msg {
	t.Helper()
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	c := &mdns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS query %s %s: %v", name, mdns.TypeToString[qtype], err)
	}
	return resp
}

func hasRRType(rrs []mdns.RR, want uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == want {
			return true
		}
	}
	return false
}

func generatePinnedSelfSignedCert(t *testing.T, dir, fqdn string) (certFile, keyFile string, spki [32]byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: fqdn},
		DNSNames:              []string{fqdn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func fetchResolveProof(ctx context.Context, seqURL, fqdn, zone string) (*types.PGNSRegistrationProof, pgns.PortalLeafRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, seqURL+types.PathV1ResolvePrefix+url.PathEscape(fqdn), nil)
	if err != nil {
		return nil, pgns.PortalLeafRecord{}, err
	}
	resp, err := utils.NewHTTPClient(utils.WithHTTPTimeout(5 * time.Second)).Do(req)
	if err != nil {
		return nil, pgns.PortalLeafRecord{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, pgns.PortalLeafRecord{}, fmt.Errorf("resolve status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, pgns.PortalLeafRecord{}, err
	}
	bundle, err := pgns.UnmarshalResolveBundle(raw)
	if err != nil {
		return nil, pgns.PortalLeafRecord{}, err
	}
	leaf, err := pgns.UnmarshalCanonicalLeaf(bundle.Leaf)
	if err != nil {
		return nil, pgns.PortalLeafRecord{}, err
	}
	return &types.PGNSRegistrationProof{
		Zone:           zone,
		Leaf:           bundle.Leaf,
		InclusionProof: bundle.InclusionProof,
		Checkpoint:     bundle.SignedCheckpoint,
	}, leaf, nil
}

func submitLeafTxToSequencer(ctx context.Context, seqURL string, tx pgns.LeafTx) error {
	raw, err := tx.MarshalCanonical()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, seqURL+"/v1/submit", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := utils.NewHTTPClient(utils.WithHTTPTimeout(5 * time.Second)).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit tx HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func waitForLeafSeq(t *testing.T, seqURL, fqdn, zone string, minSeq uint64) pgns.PortalLeafRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		_, leaf, err := fetchResolveProof(context.Background(), seqURL, fqdn, zone)
		if err == nil && leaf.Seq >= minSeq {
			return leaf
		}
		if !time.Now().Before(deadline) {
			break
		}
		<-tick.C
	}
	t.Fatalf("timed out waiting for %s seq >= %d", fqdn, minSeq)
	return pgns.PortalLeafRecord{}
}

func TestPGNSLifecycleDNSSECFailoverAndColdRecoveryE2E(t *testing.T) {
	const zone = "portal.example"
	const alias = "myapp"
	fqdn := alias + ".app." + zone

	ws, witnessSpecs, seq, seqURL, dnsSrv, dnsAddr := startTestPGNSControlPlane(t, zone)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, r1Addr, r1URL := startUntrustedRelay(t, ctx, ws)
	_, r2Addr, r2URL := startUntrustedRelay(t, ctx, ws)

	origin, _ := listenOriginService(t, "127.0.0.1")
	defer origin.Close()

	masterID, err := identity.Generate(alias)
	if err != nil {
		t.Fatal(err)
	}
	recoveryID, err := identity.Generate("cold")
	if err != nil {
		t.Fatal(err)
	}
	coldRaw, err := hex.DecodeString(strings.TrimPrefix(recoveryID.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	coldPriv := secp256k1.PrivKeyFromBytes(coldRaw)
	recoveryPubHex := hex.EncodeToString(coldPriv.PubKey().SerializeCompressed())

	pgnsStateDir := filepath.Join(t.TempDir(), "pgns-state")
	off := false
	spec, err := (tunnel.Config{
		TargetAddr:           origin.URL,
		IdentityJSON:         fmt.Sprintf(`{"name":%q,"address":%q,"public_key":%q,"private_key":%q}`, masterID.Name, masterID.Address, masterID.PublicKey, masterID.PrivateKey),
		RelayURLs:            []string{r1URL, r2URL},
		Discovery:            &off,
		PGNSZone:             zone,
		PGNSAlias:            alias,
		PGNSSequencers:       []string{seqURL},
		PGNSWitnesses:        witnessSpecs,
		PGNSWitnessThreshold: 2,
		PGNSStateDir:         pgnsStateDir,
		PGNSRecoveryPubKey:   recoveryPubHex,
		PGNSRelayEndpoints: []string{
			r1URL + "=93.184.216.34:443",
			r2URL + "=1.1.1.1:443",
		},
	}).Spec()
	if err != nil {
		t.Fatalf("Config.Spec(): %v", err)
	}

	rt1, err := tunnel.Start(ctx, spec)
	if err != nil {
		t.Fatalf("tunnel.Start: %v", err)
	}
	rt1Done := make(chan error, 1)
	go func() { rt1Done <- rt1.Run(ctx) }()
	t.Cleanup(func() {
		_ = rt1.Close()
		<-rt1Done
	})

	readyCtx, cancelReady := context.WithTimeout(ctx, 10*time.Second)
	relays, err := rt1.Exposure.WaitReady(readyCtx)
	cancelReady()
	if err != nil || len(relays) == 0 {
		t.Fatalf("WaitReady: err=%v relays=%+v", err, relays)
	}

	// 1. Verify epoch 0 in pgns/dns (A, HTTPS, dual CAA, NSEC3 NXDOMAIN, ENT NOERROR).
	syncDNSEpoch(t, seq, dnsSrv, 0)
	aResp := queryDNS(t, dnsAddr, fqdn, mdns.TypeA)
	if aResp.Rcode != mdns.RcodeSuccess || !hasRRType(aResp.Answer, mdns.TypeA) || !hasRRType(aResp.Answer, mdns.TypeRRSIG) {
		t.Fatalf("unexpected A response: %+v", aResp)
	}
	if aRR := aResp.Answer[0].(*mdns.A); aRR.A.String() != "93.184.216.34" {
		t.Fatalf("primary A record = %s, want 93.184.216.34", aRR.A.String())
	}
	httpsResp := queryDNS(t, dnsAddr, fqdn, mdns.TypeHTTPS)
	if !hasRRType(httpsResp.Answer, mdns.TypeHTTPS) || !hasRRType(httpsResp.Answer, mdns.TypeRRSIG) {
		t.Fatalf("unexpected HTTPS response: %+v", httpsResp)
	}
	caaResp := queryDNS(t, dnsAddr, fqdn, mdns.TypeCAA)
	if !hasRRType(caaResp.Answer, mdns.TypeCAA) || !hasRRType(caaResp.Answer, mdns.TypeRRSIG) {
		t.Fatalf("unexpected CAA response: %+v", caaResp)
	}
	nxResp := queryDNS(t, dnsAddr, "missing.app."+zone, mdns.TypeA)
	if nxResp.Rcode != mdns.RcodeNameError || !hasRRType(nxResp.Ns, mdns.TypeNSEC3) {
		t.Fatalf("unexpected NXDOMAIN NSEC3 response: %+v", nxResp)
	}
	entResp := queryDNS(t, dnsAddr, "app."+zone, mdns.TypeA)
	if entResp.Rcode != mdns.RcodeSuccess || len(entResp.Answer) != 0 || !hasRRType(entResp.Ns, mdns.TypeNSEC3) {
		t.Fatalf("unexpected ENT NOERROR response: %+v", entResp)
	}

	// 2. Stock browser HTTP/2 TLS traffic over R1 SNI ingress using Local TLS leaf cert.
	certPEM, err := os.ReadFile(filepath.Join(pgnsStateDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to parse pgns cert.pem")
	}
	browserClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: fqdn,
				MinVersion: tls.VersionTLS13,
				NextProtos: []string{"h2", "http/1.1"},
			},
			DialContext: func(dctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(dctx, network, r1Addr)
			},
		},
	}
	bResp, err := browserClient.Get("https://" + fqdn + "/hello")
	if err != nil {
		t.Fatalf("browser HTTP/2 GET: %v", err)
	}
	bBody, _ := io.ReadAll(bResp.Body)
	_ = bResp.Body.Close()
	if bResp.ProtoMajor != 2 || string(bBody) != marker {
		t.Fatalf("browser response proto=%s body=%q, want HTTP/2 %q", bResp.Proto, string(bBody), marker)
	}

	// 3. Native PGNS SDK client + TLS-complete Happy Eyeballs failover (250ms stagger).
	var dialMu sync.Mutex
	r1Target := r1Addr
	dialOverride := func(dctx context.Context, network, addr string) (net.Conn, error) {
		dialMu.Lock()
		curR1 := r1Target
		dialMu.Unlock()
		switch addr {
		case "93.184.216.34:443":
			return (&net.Dialer{}).DialContext(dctx, network, curR1)
		case "1.1.1.1:443":
			return (&net.Dialer{}).DialContext(dctx, network, r2Addr)
		default:
			return nil, fmt.Errorf("unexpected external dial target %s", addr)
		}
	}
	resolver, err := sdk.NewPGNSResolver(sdk.PGNSResolverConfig{
		Zone:        zone,
		Witnesses:   ws,
		ResolveURLs: []string{seqURL},
		DialContext: dialOverride,
	})
	if err != nil {
		t.Fatal(err)
	}
	pgnsClient := sdk.NewPGNSHTTPClient(resolver)
	pResp, err := pgnsClient.Get("https://" + fqdn + "/")
	if err != nil {
		t.Fatalf("PGNS client GET via R1: %v", err)
	}
	pBody, _ := io.ReadAll(pResp.Body)
	_ = pResp.Body.Close()
	if string(pBody) != marker {
		t.Fatalf("PGNS client body = %q, want %q", string(pBody), marker)
	}

	// Blackhole TLS ServerHello on R1 target (accept TCP and stall): Happy Eyeballs fails over to R2.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stallLn.Close() })
	var stalledAccepts atomic.Int32
	go func() {
		for {
			conn, aErr := stallLn.Accept()
			if aErr != nil {
				return
			}
			stalledAccepts.Add(1)
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	dialMu.Lock()
	r1Target = stallLn.Addr().String()
	dialMu.Unlock()
	pgnsClient.CloseIdleConnections()

	heResp, err := pgnsClient.Get("https://" + fqdn + "/")
	if err != nil {
		t.Fatalf("PGNS Happy Eyeballs failover GET failed: %v", err)
	}
	heBody, _ := io.ReadAll(heResp.Body)
	_ = heResp.Body.Close()
	if stalledAccepts.Load() < 1 || string(heBody) != marker {
		t.Fatalf("Happy Eyeballs failover stalledAccepts=%d body=%q", stalledAccepts.Load(), string(heBody))
	}

	dialMu.Lock()
	r1Target = r1Addr
	dialMu.Unlock()
	pgnsClient.CloseIdleConnections()

	// 4. Verify ACME DNS-01 + PERSIST01 + pinned CAA publication in pgns/dns.
	oldSitePriv, _, _, err := func() (*secp256k1.PrivateKey, string, string, error) {
		raw, err := hex.DecodeString(strings.TrimPrefix(masterID.PrivateKey, "0x"))
		if err != nil {
			return nil, "", "", err
		}
		k, err := pgns.DeriveAppSiteKey(secp256k1.PrivKeyFromBytes(raw), fqdn)
		return k, fqdn, alias, err
	}()
	if err != nil {
		t.Fatal(err)
	}
	oldProof, leaf1, err := fetchResolveProof(ctx, seqURL, fqdn, zone)
	if err != nil {
		t.Fatal(err)
	}
	acmeDigest := sha256.Sum256([]byte("acme-key-auth-e2e"))
	acmeLeaf := leaf1
	acmeLeaf.Seq = leaf1.Seq + 1
	acmeLeaf.IssuedAt = uint64(time.Now().UTC().Unix())
	acmeLeaf.ExpiresAt = acmeLeaf.IssuedAt + 3600
	acmeLeaf.Flags |= pgns.FlagPersist01Enabled
	acmeLeaf.ACMECAIssuer = "pki.goog"
	acmeLeaf.ACMEAccountURI = "https://dv.acme-v02.api.pki.goog/acme/acct/773"
	acmeLeaf.ACMEDNS01Digest = acmeDigest
	acmeTx := pgns.LeafTx{TxType: pgns.TxTypeUpdate, Leaf: acmeLeaf}
	if err := acmeTx.SignOwner(oldSitePriv); err != nil {
		t.Fatal(err)
	}
	if err := submitLeafTxToSequencer(ctx, seqURL, acmeTx); err != nil {
		t.Fatalf("submit ACME update tx: %v", err)
	}
	waitForLeafSeq(t, seqURL, fqdn, zone, 2)
	syncDNSEpoch(t, seq, dnsSrv, 1)

	txtResp := queryDNS(t, dnsAddr, "_acme-challenge."+fqdn, mdns.TypeTXT)
	if !hasRRType(txtResp.Answer, mdns.TypeTXT) || !hasRRType(txtResp.Answer, mdns.TypeRRSIG) {
		t.Fatalf("missing _acme-challenge TXT/RRSIG: %+v", txtResp)
	}
	wantTXT := base64.RawURLEncoding.EncodeToString(acmeDigest[:])
	if gotTXT := txtResp.Answer[0].(*mdns.TXT).Txt[0]; gotTXT != wantTXT {
		t.Fatalf("_acme-challenge TXT = %q, want %q", gotTXT, wantTXT)
	}
	persistResp := queryDNS(t, dnsAddr, "_validation-persist."+fqdn, mdns.TypeTXT)
	if !hasRRType(persistResp.Answer, mdns.TypeTXT) || !hasRRType(persistResp.Answer, mdns.TypeRRSIG) {
		t.Fatalf("missing _validation-persist TXT/RRSIG: %+v", persistResp)
	}
	caaPinnedResp := queryDNS(t, dnsAddr, fqdn, mdns.TypeCAA)
	var sawWildDeny, sawPinnedIssue bool
	for _, rr := range caaPinnedResp.Answer {
		caa, ok := rr.(*mdns.CAA)
		if !ok {
			continue
		}
		if caa.Tag == "issuewild" && caa.Value == ";" {
			sawWildDeny = true
		}
		if caa.Tag == "issue" && strings.Contains(caa.Value, "pki.goog") && strings.Contains(caa.Value, "validationmethods=dns-01") {
			sawPinnedIssue = true
		}
	}
	if !sawWildDeny || !sawPinnedIssue {
		t.Fatalf("expected dual pinned CAA records, got: %+v", caaPinnedResp.Answer)
	}

	// 5. Offline ColdRecovery preemption on R1 + compromised old-key watermark fencing.
	newSiteID, err := identity.Generate(alias)
	if err != nil {
		t.Fatal(err)
	}
	newSiteRaw, err := hex.DecodeString(strings.TrimPrefix(newSiteID.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	newSitePriv := secp256k1.PrivKeyFromBytes(newSiteRaw)
	var newSitePub33 [33]byte
	copy(newSitePub33[:], newSitePriv.PubKey().SerializeCompressed())

	cert2File, key2File, spki2 := generatePinnedSelfSignedCert(t, t.TempDir(), fqdn)
	nowRecover := uint64(time.Now().UTC().Unix())
	recLeaf := acmeLeaf
	recLeaf.Seq = acmeLeaf.Seq + 10
	recLeaf.IssuedAt = nowRecover
	recLeaf.ExpiresAt = nowRecover + 3600
	recLeaf.OwnerPubKey = newSitePub33
	recLeaf.TLSSPKISHA256 = spki2
	recLeaf.NextTLSSPKISHA256 = [32]byte{}
	recLeaf.ACMEDNS01Digest = [32]byte{}
	recTx := pgns.LeafTx{
		TxType:   pgns.TxTypeColdRecovery,
		Leaf:     recLeaf,
		PoWNonce: 0,
	}
	if err := recTx.SignOwner(newSitePriv); err != nil {
		t.Fatal(err)
	}
	if err := recTx.SignRecovery(coldPriv); err != nil {
		t.Fatal(err)
	}
	if err := submitLeafTxToSequencer(ctx, seqURL, recTx); err != nil {
		t.Fatalf("submit ColdRecovery tx: %v", err)
	}
	waitForLeafSeq(t, seqURL, fqdn, zone, recLeaf.Seq)

	// Expose recovered identity directly against R1 while rt1 still holds the old lease.
	const recoveredMarker = "pgns-recovered-ok"
	recoveredExp, err := sdk.Expose(
		ctx,
		newSiteID,
		[]string{r1URL},
		sdk.WithTLSCertificate(cert2File, key2File),
		sdk.WithPGNS(fqdn, func(pctx context.Context) (*types.PGNSRegistrationProof, error) {
			proof, _, err := fetchResolveProof(pctx, seqURL, fqdn, zone)
			return proof, err
		}),
	)
	if err != nil {
		t.Fatalf("expose recovered lease on R1: %v", err)
	}
	recHTTPDone := make(chan error, 1)
	go func() {
		recHTTPDone <- sdk.RunHTTP(ctx, recoveredExp, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, recoveredMarker)
		}), "")
	}()
	t.Cleanup(func() {
		_ = recoveredExp.Close()
		<-recHTTPDone
	})
	recReadyCtx, cancelRecReady := context.WithTimeout(ctx, 10*time.Second)
	if _, err := recoveredExp.WaitReady(recReadyCtx); err != nil {
		cancelRecReady()
		t.Fatalf("recovered WaitReady: %v", err)
	}
	cancelRecReady()

	recResp, err := pgnsClient.Get("https://" + fqdn + "/")
	if err != nil {
		t.Fatalf("PGNS client GET after ColdRecovery preemption: %v", err)
	}
	recBody, _ := io.ReadAll(recResp.Body)
	_ = recResp.Body.Close()
	if string(recBody) != recoveredMarker {
		t.Fatalf("recovered body = %q, want %q", string(recBody), recoveredMarker)
	}

	// Re-attempting /sdk/register on R1 using the compromised old key and stale seq=1 proof
	// must fail with APIErrorCodePGNSWatermarkStale.
	assertStaleProofRejected(t, ctx, r1URL, rt1.Identity, oldProof)
}

func TestPGNSUnnamedDefaultIDTunnelE2E(t *testing.T) {
	const zone = "portal.example"
	ws, witnessSpecs, seq, seqURL, dnsSrv, dnsAddr := startTestPGNSControlPlane(t, zone)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	_, r1Addr, r1URL := startUntrustedRelay(t, ctx, ws)
	origin, _ := listenOriginService(t, "127.0.0.1")
	defer origin.Close()

	masterID, err := identity.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	rawMaster, err := hex.DecodeString(strings.TrimPrefix(masterID.PrivateKey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	sitePriv, err := pgns.DeriveIDSiteKey(secp256k1.PrivKeyFromBytes(rawMaster), zone, "")
	if err != nil {
		t.Fatal(err)
	}
	var sitePub33 [33]byte
	copy(sitePub33[:], sitePriv.PubKey().SerializeCompressed())
	idTag, err := pgns.DeriveIDTag(sitePub33)
	if err != nil {
		t.Fatal(err)
	}
	fqdn := types.UnnamedServiceLabel + "." + idTag + ".id." + zone

	off := false
	spec, err := (tunnel.Config{
		TargetAddr:           origin.URL,
		IdentityJSON:         fmt.Sprintf(`{"name":"","address":%q,"public_key":%q,"private_key":%q}`, masterID.Address, masterID.PublicKey, masterID.PrivateKey),
		RelayURLs:            []string{r1URL},
		Discovery:            &off,
		PGNSZone:             zone,
		PGNSSequencers:       []string{seqURL},
		PGNSWitnesses:        witnessSpecs,
		PGNSWitnessThreshold: 2,
		PGNSStateDir:         filepath.Join(t.TempDir(), "pgns-unnamed-state"),
		PGNSRelayEndpoints:   []string{r1URL + "=93.184.216.34:443"},
	}).Spec()
	if err != nil {
		t.Fatalf("unnamed Config.Spec(): %v", err)
	}

	rt, err := tunnel.Start(ctx, spec)
	if err != nil {
		t.Fatalf("unnamed tunnel.Start: %v", err)
	}
	rtDone := make(chan error, 1)
	go func() { rtDone <- rt.Run(ctx) }()
	t.Cleanup(func() {
		_ = rt.Close()
		<-rtDone
	})

	readyCtx, cancelReady := context.WithTimeout(ctx, 10*time.Second)
	if _, err := rt.Exposure.WaitReady(readyCtx); err != nil {
		cancelReady()
		t.Fatalf("unnamed WaitReady: %v", err)
	}
	cancelReady()

	syncDNSEpoch(t, seq, dnsSrv, 0)
	aResp := queryDNS(t, dnsAddr, fqdn, mdns.TypeA)
	if aResp.Rcode != mdns.RcodeSuccess || !hasRRType(aResp.Answer, mdns.TypeA) {
		t.Fatalf("unnamed default .id A query failed: %+v", aResp)
	}

	resolver, err := sdk.NewPGNSResolver(sdk.PGNSResolverConfig{
		Zone:        zone,
		Witnesses:   ws,
		ResolveURLs: []string{seqURL},
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "93.184.216.34:443" {
				return nil, fmt.Errorf("unexpected target %s", addr)
			}
			return (&net.Dialer{}).DialContext(dctx, network, r1Addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sdk.NewPGNSHTTPClient(resolver).Get("https://" + fqdn + "/")
	if err != nil {
		t.Fatalf("unnamed PGNS HTTP GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != marker {
		t.Fatalf("unnamed PGNS HTTP body = %q, want %q", string(body), marker)
	}
}

func assertStaleProofRejected(t *testing.T, ctx context.Context, relayURL string, oldID types.Identity, staleProof *types.PGNSRegistrationProof) {
	t.Helper()
	parsed, err := url.Parse(relayURL)
	if err != nil {
		t.Fatal(err)
	}
	_, httpClient, transport, err := utils.NewHTTPTLSClient(ctx, parsed, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()

	var challenge types.RegisterChallengeResponse
	chalReq := types.RegisterChallengeRequest{
		Namespace: types.LocalTLSNamespaceV1,
		Identity:  oldID,
		TTL:       60,
	}
	if err := utils.HTTPDoAPIPath(ctx, httpClient, parsed, http.MethodPost, types.PathSDKRegisterChallenge, chalReq, nil, &challenge); err != nil {
		t.Fatalf("challenge for old key: %v", err)
	}
	sig, err := identity.NewLocalAuthority(oldID).SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	regReq := types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: sig,
		PGNSProof:     staleProof,
	}
	var regResp types.RegisterResponse
	regErr := utils.HTTPDoAPIPath(ctx, httpClient, parsed, http.MethodPost, types.PathSDKRegister, regReq, nil, &regResp)
	if regErr == nil {
		t.Fatal("expected compromised old key registration with stale proof to be rejected")
	}
	apiErr, ok := errors.AsType[*types.APIRequestError](regErr)
	if !ok || apiErr.Code != types.APIErrorCodePGNSWatermarkStale {
		t.Fatalf("register error = %v, want APIErrorCodePGNSWatermarkStale (%s)", regErr, types.APIErrorCodePGNSWatermarkStale)
	}
}
