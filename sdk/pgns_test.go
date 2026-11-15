package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func makePGNSWitnessFixture(t *testing.T, fqdn string, now time.Time) (pgns.WitnessSet, pgns.PortalLeafRecord, types.Identity, tls.Certificate, func(epoch uint64, cpTS uint64) []byte) {
	t.Helper()

	id, err := identity.Generate("pgnsapp")
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := hex.DecodeString(strings.TrimPrefix(id.PublicKey, "0x"))
	if err != nil || len(pubBytes) != 33 {
		t.Fatalf("decode pubkey: %v len=%d", err, len(pubBytes))
	}
	var ownerPub [33]byte
	copy(ownerPub[:], pubBytes)

	tlsCert := makeSelfSignedTLSCert(t, fqdn)
	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(parsedCert.RawSubjectPublicKeyInfo)

	issued := uint64(now.UTC().Unix())
	leaf := pgns.PortalLeafRecord{
		Version:       pgns.LeafVersion,
		Flags:         pgns.FlagHTTP2,
		FQDN:          fqdn,
		Seq:           1,
		IssuedAt:      issued,
		ExpiresAt:     issued + 3600,
		OwnerPubKey:   ownerPub,
		TLSSPKISHA256: spki,
		Endpoints: []pgns.Endpoint{
			{
				RelayID:  [20]byte{0x01},
				IPv4:     [4]byte{1, 1, 1, 1},
				Port:     443,
				Priority: 10,
			},
			{
				RelayID:  [20]byte{0x02},
				IPv4:     [4]byte{8, 8, 8, 8},
				Port:     443,
				Priority: 20,
			},
		},
	}

	rawLeaf, err := leaf.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	smt := pgns.NewSparseMerkleTree()
	smt.Put(pgns.SMTKey(fqdn), rawLeaf)
	proof, err := smt.Prove(pgns.SMTKey(fqdn))
	if err != nil {
		t.Fatal(err)
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	w1Pub, w1Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w2Pub, w2Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ws := pgns.WitnessSet{
		Threshold: 2,
		Witnesses: []pgns.WitnessKey{
			{Name: "w1", PublicKey: w1Pub},
			{Name: "w2", PublicKey: w2Pub},
		},
	}

	const zone = "portal.example"
	recHash := sha256.Sum256([]byte("test-epoch"))
	logRoot, _, err := pgns.ComputeAppendLogRoot(0, recHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = tlog.Hash{}

	buildBundle := func(epoch, cpTS uint64) []byte {
		cp := pgns.Checkpoint{
			Origin:    pgns.CheckpointOriginPrefix + zone,
			LogSize:   epoch + 1,
			LogRoot:   logRoot,
			Epoch:     epoch,
			Timestamp: cpTS,
			SMTRoot:   smt.Root(),
		}
		body := cp.FormatBody()
		c1, err := pgns.CosignCheckpoint(body, ws.Witnesses[0], w1Priv, cpTS)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := pgns.CosignCheckpoint(body, ws.Witnesses[1], w2Priv, cpTS)
		if err != nil {
			t.Fatal(err)
		}
		rawCP := pgns.FormatSignedCheckpoint(body, []pgns.WitnessCosignature{c1, c2})
		rawBundle, err := pgns.ResolveBundle{
			Leaf:             rawLeaf,
			InclusionProof:   proofBytes,
			SignedCheckpoint: rawCP,
		}.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return rawBundle
	}

	return ws, leaf, id, tlsCert, buildBundle
}

func TestPGNSResolverVerificationAndAntiRollback(t *testing.T) {
	const (
		zone = "portal.example"
		fqdn = "myapp.app.portal.example"
	)
	now := time.Now().UTC()
	nowSec := uint64(now.Unix())
	ws, _, _, _, buildBundle := makePGNSWitnessFixture(t, fqdn, now)

	var served []byte
	mirrorFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "mirror unavailable", http.StatusServiceUnavailable)
	}))
	defer mirrorFail.Close()

	mirrorOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != types.PathV1ResolvePrefix+fqdn {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(served)
	}))
	defer mirrorOK.Close()

	resolver, err := NewPGNSResolver(PGNSResolverConfig{
		Zone:        zone,
		Witnesses:   ws,
		ResolveURLs: []string{mirrorFail.URL, mirrorOK.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mirror 1 fails, Mirror 2 succeeds at epoch 5.
	served = buildBundle(5, nowSec)
	leaf, cp, err := resolver.Resolve(t.Context(), fqdn)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if leaf.FQDN != fqdn || cp.Epoch != 5 {
		t.Fatalf("Resolve() got (fqdn=%q epoch=%d), want (%q, 5)", leaf.FQDN, cp.Epoch, fqdn)
	}

	// Anti-rollback: older signed epoch 4 must be rejected.
	served = buildBundle(4, nowSec)
	if _, _, err := resolver.Resolve(t.Context(), fqdn); !errors.Is(err, pgns.ErrStaleCheckpoint) {
		t.Fatalf("Resolve(rollback) = %v, want ErrStaleCheckpoint", err)
	}

	// Freshness window limits: future skew (> +60s) and stale age (> 600s) rejected.
	served = buildBundle(6, uint64(time.Now().UTC().Unix())+75)
	if _, _, err := resolver.Resolve(t.Context(), fqdn); !errors.Is(err, pgns.ErrStaleCheckpoint) {
		t.Fatalf("Resolve(future skew) = %v, want ErrStaleCheckpoint", err)
	}
	served = buildBundle(6, uint64(time.Now().UTC().Unix())-615)
	if _, _, err := resolver.Resolve(t.Context(), fqdn); !errors.Is(err, pgns.ErrStaleCheckpoint) {
		t.Fatalf("Resolve(stale age) = %v, want ErrStaleCheckpoint", err)
	}
}

func TestPGNSLeafValidationRejectsPrivateIPsAndZeroPort(t *testing.T) {
	cases := []struct {
		name string
		ep   pgns.Endpoint
	}{
		{"loopback ipv4", pgns.Endpoint{IPv4: [4]byte{127, 0, 0, 1}, Port: 443}},
		{"rfc1918 10/8", pgns.Endpoint{IPv4: [4]byte{10, 0, 0, 1}, Port: 443}},
		{"imds link-local", pgns.Endpoint{IPv4: [4]byte{169, 254, 169, 254}, Port: 443}},
		{"loopback ipv6", pgns.Endpoint{IPv6: [16]byte{15: 1}, Port: 443}},
		{"ula ipv6", pgns.Endpoint{IPv6: [16]byte{0xfd, 0x00, 15: 1}, Port: 443}},
		{"zero port", pgns.Endpoint{IPv4: [4]byte{1, 1, 1, 1}, Port: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := pgns.PortalLeafRecord{Endpoints: []pgns.Endpoint{tc.ep}}
			if _, err := pgnsCandidateTargets(leaf); !errors.Is(err, pgns.ErrInvalidEndpoint) {
				t.Fatalf("pgnsCandidateTargets(%s) = %v, want ErrInvalidEndpoint", tc.name, err)
			}
		})
	}
}

func startPGNSLoopbackTunnel(t *testing.T, id types.Identity, fqdn string, cert tls.Certificate) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	l := &listener{
		identity: id,
		lease:    utils.NewSnapshot(listenerSnapshot{hostname: fqdn, pgnsFQDN: fqdn, accessToken: "test-access-token"}),
	}
	l.mitmManager = newMITMManager(l, false)

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1", types.ALPNPortalCBV1},
					MinVersion:   tls.VersionTLS13,
				})
				if err := tlsConn.Handshake(); err != nil {
					_ = tlsConn.Close()
					return
				}
				nextConn, handled, err := l.mitmManager.maybeHandleConn(tlsConn)
				if err != nil || handled {
					return
				}
				defer nextConn.Close()
				var buf [4]byte
				if _, err := io.ReadFull(nextConn, buf[:]); err != nil {
					return
				}
				_, _ = nextConn.Write([]byte("ok:" + string(buf[:])))
			}(raw)
		}
	}()
	return ln
}

func TestDialPGNSSPKIPinningAndRotation(t *testing.T) {
	const (
		zone = "portal.example"
		fqdn = "myapp.app.portal.example"
	)
	now := time.Now().UTC()
	ws, baseLeaf, id, currentCert, _ := makePGNSWitnessFixture(t, fqdn, now)

	nextCert := makeSelfSignedTLSCert(t, fqdn)
	nextParsed, err := x509.ParseCertificate(nextCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	nextSPKI := sha256.Sum256(nextParsed.RawSubjectPublicKeyInfo)
	wrongCert := makeSelfSignedTLSCert(t, fqdn)

	leaf := baseLeaf
	leaf.NextTLSSPKISHA256 = nextSPKI
	leaf.Endpoints = leaf.Endpoints[:1] // single endpoint 1.1.1.1:443
	_ = ws

	serveWithCert := func(cert tls.Certificate) func(context.Context, string, string) (net.Conn, error) {
		ln := startPGNSLoopbackTunnel(t, id, fqdn, cert)
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "1.1.1.1:443" {
				return nil, errors.New("unexpected dial target: " + addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		}
	}

	// Current TLSSPKISHA256 succeeds.
	conn1, err := dialPGNSLeaf(t.Context(), leaf, fqdn, serveWithCert(currentCert))
	if err != nil {
		t.Fatalf("dialPGNSLeaf(currentCert) = %v", err)
	}
	_, _ = conn1.Write([]byte("ping"))
	var reply [7]byte
	if _, err := io.ReadFull(conn1, reply[:]); err != nil || string(reply[:]) != "ok:ping" {
		t.Fatalf("reply = %q, %v", reply[:], err)
	}
	_ = conn1.Close()

	// NextTLSSPKISHA256 succeeds during rotation overlap.
	conn2, err := dialPGNSLeaf(t.Context(), leaf, fqdn, serveWithCert(nextCert))
	if err != nil {
		t.Fatalf("dialPGNSLeaf(nextCert) = %v", err)
	}
	_ = conn2.Close()

	// Unpinned SPKI is rejected even with valid owner key signature capability.
	if _, err := dialPGNSLeaf(t.Context(), leaf, fqdn, serveWithCert(wrongCert)); !errors.Is(err, errPGNSSPKIMismatch) {
		t.Fatalf("dialPGNSLeaf(wrongCert) = %v, want errPGNSSPKIMismatch", err)
	}
}

func TestDialPGNSHappyEyeballsBlackholeFailover(t *testing.T) {
	const (
		zone = "portal.example"
		fqdn = "myapp.app.portal.example"
	)
	now := time.Now().UTC()
	ws, baseLeaf, id, cert, buildBundle := makePGNSWitnessFixture(t, fqdn, now)
	_ = baseLeaf

	// Primary blackhole listener accepts TCP SYN-ACK then holds the connection silent.
	blackholeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackholeLn.Close()
	var blackholeConns atomic.Int32
	go func() {
		for {
			c, err := blackholeLn.Accept()
			if err != nil {
				return
			}
			blackholeConns.Add(1)
			go func(conn net.Conn) {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}(c)
		}
	}()

	secondaryLn := startPGNSLoopbackTunnel(t, id, fqdn, cert)

	bundleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buildBundle(0, uint64(time.Now().UTC().Unix())))
	}))
	defer bundleServer.Close()

	var secondaryConns atomic.Int32
	resolver, err := NewPGNSResolver(PGNSResolverConfig{
		Zone:        zone,
		Witnesses:   ws,
		ResolveURLs: []string{bundleServer.URL},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case "1.1.1.1:443":
				return (&net.Dialer{}).DialContext(ctx, network, blackholeLn.Addr().String())
			case "8.8.8.8:443":
				secondaryConns.Add(1)
				return (&net.Dialer{}).DialContext(ctx, network, secondaryLn.Addr().String())
			default:
				return nil, errors.New("unexpected target: " + addr)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := DialPGNS(ctx, resolver, fqdn)
	if err != nil {
		t.Fatalf("DialPGNS() error = %v", err)
	}
	defer conn.Close()

	if blackholeConns.Load() == 0 {
		t.Fatal("primary blackhole endpoint was never dialed")
	}
	if secondaryConns.Load() == 0 {
		t.Fatal("secondary fallback endpoint was never dialed")
	}
	if _, err := conn.Write([]byte("helo")); err != nil {
		t.Fatal(err)
	}
	var got [7]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil {
		t.Fatal(err)
	}
	if string(got[:]) != "ok:helo" {
		t.Fatalf("reply = %q, want ok:helo", got[:])
	}
}

func TestExposeWithPGNSValidation(t *testing.T) {
	cert := makeSelfSignedTLSCert(t, "myapp.app.portal.example")
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	dummyProvider := func(context.Context) (*types.PGNSRegistrationProof, error) {
		return &types.PGNSRegistrationProof{}, nil
	}

	base := options{
		pgnsConfigured: true,
		PGNSFQDN:       "myapp.app.portal.example",
		PGNSProvider:   dummyProvider,
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
	}

	// Missing local certificate is rejected.
	noCert := base
	noCert.TLSCertFile, noCert.TLSKeyFile = "", ""
	if err := validateExposeConfig(noCert); !errors.Is(err, errPGNSRequiresLocalCertificate) {
		t.Fatalf("missing cert err = %v, want errPGNSRequiresLocalCertificate", err)
	}

	// Nil provider is rejected.
	noProv := base
	noProv.PGNSProvider = nil
	if err := validateExposeConfig(noProv); !errors.Is(err, errPGNSProviderRequired) {
		t.Fatalf("nil provider err = %v, want errPGNSProviderRequired", err)
	}

	// Incompatible with static relay cache.
	withCache := base
	withCache.Cache = &cache.SourceConfig{}
	if err := validateExposeConfig(withCache); !errors.Is(err, errPGNSModeUnsupported) {
		t.Fatalf("with cache err = %v, want errPGNSModeUnsupported", err)
	}

	// Incompatible with WithTCP.
	withTCP := base
	withTCP.TCPEnabled = true
	if err := validateExposeConfig(withTCP); !errors.Is(err, errPGNSModeUnsupported) {
		t.Fatalf("with tcp err = %v, want errPGNSModeUnsupported", err)
	}
}

type pgnsTestExposureListener struct {
	net.Listener
	tlsConf *tls.Config
	l       *listener
}

func (p pgnsTestExposureListener) Accept() (net.Conn, error) {
	for {
		raw, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Server(raw, p.tlsConf.Clone())
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			continue
		}
		nextConn, handled, err := p.l.mitmManager.maybeHandleConn(tlsConn)
		if err != nil || handled {
			if err != nil {
				_ = tlsConn.Close()
			}
			continue
		}
		return &exposureConn{Conn: nextConn}, nil
	}
}

func TestRunHTTPServesPGNSChannelBoundConnAndBlocksPlaintextDowngrade(t *testing.T) {
	const (
		zone = "portal.example"
		fqdn = "myapp.app.portal.example"
	)
	now := time.Now().UTC()
	ws, _, id, cert, buildBundle := makePGNSWitnessFixture(t, fqdn, now)
	parsedLeaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedLeaf)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1", types.ALPNPortalCBV1},
		MinVersion:   tls.VersionTLS13,
	}

	l := &listener{
		identity: id,
		lease: utils.NewSnapshot(listenerSnapshot{
			hostname:    fqdn,
			pgnsFQDN:    fqdn,
			accessToken: "test-access-token",
		}),
	}
	l.mitmManager = newMITMManager(l, false)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	var plainHits atomic.Int32
	plainTrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer plainTrap.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- RunHTTP(ctx, pgnsTestExposureListener{Listener: tcpLn, tlsConf: serverTLS, l: l}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || r.TLS.ServerName != fqdn {
				http.Error(w, "missing TLS state", http.StatusBadRequest)
				return
			}
			if r.URL.Path == "/downgrade" {
				http.Redirect(w, r, plainTrap.URL+"/leak", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("hello:" + r.URL.Path))
		}), "")
	}()
	t.Cleanup(func() {
		cancel()
		_ = tcpLn.Close()
		<-runDone
	})

	bundleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buildBundle(0, uint64(time.Now().UTC().Unix())))
	}))
	defer bundleSrv.Close()

	resolver, err := NewPGNSResolver(PGNSResolverConfig{
		Zone:        zone,
		Witnesses:   ws,
		ResolveURLs: []string{bundleSrv.URL},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, tcpLn.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	pgnsClient := NewPGNSHTTPClient(resolver)
	if pgnsClient.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("NewPGNSHTTPClient transport must not use an HTTP proxy that bypasses DialTLSContext")
	}
	resp, err := pgnsClient.Get("https://" + fqdn + "/cb")
	if err != nil {
		t.Fatalf("NewPGNSHTTPClient GET failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello:/cb" {
		t.Fatalf("PGNS response = (%d, %q), want (200, %q)", resp.StatusCode, string(body), "hello:/cb")
	}

	// Plaintext http:// request MUST fail closed without dialing plaintext TCP.
	if _, err := pgnsClient.Get("http://" + fqdn + "/plain"); !errors.Is(err, errPGNSHTTPSRequired) {
		t.Fatalf("NewPGNSHTTPClient(http://) err = %v, want errPGNSHTTPSRequired", err)
	}

	// 302 https -> http downgrade redirect MUST fail closed without contacting plainTrap.
	if _, err := pgnsClient.Get("https://" + fqdn + "/downgrade"); !errors.Is(err, errPGNSHTTPSRequired) {
		t.Fatalf("NewPGNSHTTPClient(https->http redirect) err = %v, want errPGNSHTTPSRequired", err)
	}
	if plainHits.Load() != 0 {
		t.Fatalf("plaintext downgrade target received %d requests, want 0", plainHits.Load())
	}

	browserClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				ServerName: fqdn,
				MinVersion: tls.VersionTLS13,
				NextProtos: []string{"h2", "http/1.1"},
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, tcpLn.Addr().String())
			},
		},
	}
	bResp, err := browserClient.Get("https://" + fqdn + "/h2")
	if err != nil {
		t.Fatalf("HTTP/2 browser GET failed: %v", err)
	}
	bBody, _ := io.ReadAll(bResp.Body)
	_ = bResp.Body.Close()
	if bResp.ProtoMajor != 2 || string(bBody) != "hello:/h2" {
		t.Fatalf("browser response = (proto=%s body=%q), want (HTTP/2, %q)", bResp.Proto, string(bBody), "hello:/h2")
	}
}
