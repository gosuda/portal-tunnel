package keyless

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signrpc"
	"golang.org/x/crypto/cryptobyte"
)

const tenantHostname = "tenant.test.example"

// relayCertificate is one certificate the relay can serve: a leaf issued by the
// test CA, presented with the CA as its chain, like a renewal by the same issuer.
type relayCertificate struct {
	leaf *x509.Certificate
	tls  tls.Certificate
}

type testIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testIssuer{cert: cert, key: key, pool: pool}
}

// issue returns a new certificate for the tenant hostname with a new private
// key, as every ACME issuance does.
func (i *testIssuer) issue(t *testing.T, serial int64) relayCertificate {
	t.Helper()
	return i.issueFor(t, serial, tenantHostname)
}

func (i *testIssuer) issueFor(t *testing.T, serial int64, dnsName string) relayCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return relayCertificate{leaf: leaf, tls: tls.Certificate{Certificate: [][]byte{der, i.cert.Raw}, PrivateKey: key}}
}

// relayStandIn is a relay serving one certificate and signing transcripts with
// the real Signer for every certificate it still holds a key for.
type relayStandIn struct {
	srv      *httptest.Server
	url      string
	bindings *BindingRegistry

	mu      sync.Mutex
	serving relayCertificate
	keys    map[string]crypto.Signer
}

func newRelayStandIn(t *testing.T, first relayCertificate) *relayStandIn {
	t.Helper()
	relay := &relayStandIn{bindings: NewBindingRegistry(time.Minute), serving: first, keys: map[string]crypto.Signer{}}
	relay.keys[string(first.leaf.Raw)] = first.tls.PrivateKey.(crypto.Signer)
	signer, err := NewSigner(relay.bindings, func(leafDER []byte) crypto.Signer {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.keys[string(leafDER)]
	})
	if err != nil {
		t.Fatal(err)
	}
	relay.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != signrpc.SignPath {
			http.NotFound(w, r)
			return
		}
		signer.ServeHTTP(w, r, "lease")
	}))
	// httptest's StartTLS installs its own certificate next to GetCertificate,
	// and a client that sends no server name (an IP literal) would get that one.
	relay.srv.Listener = tls.NewListener(relay.srv.Listener, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			relay.mu.Lock()
			defer relay.mu.Unlock()
			serving := relay.serving.tls
			return &serving, nil
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	relay.srv.Start()
	t.Cleanup(relay.srv.Close)
	relay.url = "https://" + relay.srv.Listener.Addr().String()
	return relay
}

// renew makes next the served certificate. The relay signs for the replaced
// one only when retire is false.
func (r *relayStandIn) renew(next relayCertificate, retire bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if retire {
		delete(r.keys, string(r.serving.leaf.Raw))
	}
	r.serving = next
	r.keys[string(next.leaf.Raw)] = next.tls.PrivateKey.(crypto.Signer)
}

func (r *relayStandIn) newClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{RelayURL: r.url, Hostname: tenantHostname, AccessToken: "token"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// visit runs one visitor handshake through client, trusting the way a browser
// does: the presented chain must verify and the CertificateVerify signature
// must match the presented leaf. It returns the leaf the visitor was shown.
func (r *relayStandIn) visit(t *testing.T, client *Client, roots *x509.CertPool) (*x509.Certificate, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	binding := r.bindings.Issue("lease", nil)
	relayEnd, tenantEnd := net.Pipe()
	defer relayEnd.Close()
	visitor := tls.Client(r.bindings.FixHelloOnWrite(relayEnd, binding), &tls.Config{ServerName: tenantHostname, RootCAs: roots, MinVersion: tls.VersionTLS13})
	defer visitor.Close()
	visitorDone := make(chan error, 1)
	go func() { visitorDone <- visitor.HandshakeContext(ctx) }()

	terminated, err := client.TerminateConn(ctx, tenantEnd, binding[:])
	if err != nil {
		_ = relayEnd.Close()
		<-visitorDone
		return nil, err
	}
	defer terminated.Close()
	if err := <-visitorDone; err != nil {
		return nil, err
	}
	return visitor.ConnectionState().PeerCertificates[0], nil
}

// A renewal gives the relay a new certificate and key. A tenant that registered
// before it still presents the old chain, and visitors must be served with it
// until the tenant moves to the new one, while a tenant that registers after it
// presents the new chain from the start.
func TestTenantsAcrossARelayCertificateRenewal(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	before, renewed := issuer.issue(t, 2), issuer.issue(t, 3)
	relay := newRelayStandIn(t, before)
	registeredBefore := relay.newClient(t)

	relay.renew(renewed, false)

	if leaf, err := relay.visit(t, registeredBefore, issuer.pool); err != nil || !leaf.Equal(before.leaf) {
		t.Fatalf("tenant registered before the renewal: leaf %v, error %v; want the old certificate and no error", leaf, err)
	}
	registeredAfter := relay.newClient(t)
	if leaf, err := relay.visit(t, registeredAfter, issuer.pool); err != nil || !leaf.Equal(renewed.leaf) {
		t.Fatalf("tenant registered after the renewal: leaf %v, error %v; want the new certificate and no error", leaf, err)
	}

	changed, err := registeredBefore.RefreshChain(context.Background())
	if err != nil || !changed {
		t.Fatalf("RefreshChain() = %v, %v; want the new chain pinned", changed, err)
	}
	if leaf, err := relay.visit(t, registeredBefore, issuer.pool); err != nil || !leaf.Equal(renewed.leaf) {
		t.Fatalf("tenant after RefreshChain: leaf %v, error %v; want the new certificate and no error", leaf, err)
	}
	// The MITM self-probe verifies what the tenant presents against this pool.
	pinned := x509.NewCertPool()
	pinned.AddCert(renewed.leaf)
	pinned.AddCert(issuer.cert)
	if !registeredBefore.RelayCertPool().Equal(pinned) {
		t.Fatal("RelayCertPool() after RefreshChain is not the chain the tenant presents")
	}
	if changed, err := registeredBefore.RefreshChain(context.Background()); err != nil || changed {
		t.Fatalf("RefreshChain() with nothing renewed = %v, %v; want no change", changed, err)
	}
}

// Once the relay no longer holds the key of the chain a tenant presents, it
// must refuse to sign for it, even though it holds the key of the certificate it
// serves now, and the tenant must pin the served chain on that answer.
func TestClientRepinsWhenTheRelayHoldsNoKeyForItsChain(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	before, renewed := issuer.issue(t, 2), issuer.issue(t, 3)
	relay := newRelayStandIn(t, before)
	client := relay.newClient(t)

	relay.renew(renewed, true)

	if leaf, err := relay.visit(t, client, issuer.pool); err == nil || !strings.Contains(err.Error(), unknownCertificateMessage) {
		t.Fatalf("handshake with an unknown certificate: leaf %v, error %v; want the relay's refusal", leaf, err)
	}
	if leaf, err := relay.visit(t, client, issuer.pool); err != nil || !leaf.Equal(renewed.leaf) {
		t.Fatalf("handshake after the refusal: leaf %v, error %v; want the new certificate and no error", leaf, err)
	}
}

// certificateMessage builds a TLS 1.3 Certificate handshake message from DER
// certificates, the shape the tenant's t13server puts in a sign request.
func certificateMessage(entries ...[]byte) []byte {
	var list cryptobyte.Builder
	for _, entry := range entries {
		list.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(entry) })
		list.AddUint16(0)
	}
	var out cryptobyte.Builder
	out.AddUint8(handshakeTypeCertificate)
	out.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(list.BytesOrPanic()) })
	})
	return out.BytesOrPanic()
}

// The sign endpoint's answers are a wire contract with the tenants: only the
// relay key id is served, a malformed certificate message is a bad request, a
// certificate without a key is the refusal tenants re-pin on, and a known
// certificate is signed for.
func TestSignerAnswers(t *testing.T) {
	t.Parallel()

	known, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bindings := NewBindingRegistry(time.Minute)
	signer, err := NewSigner(bindings, func(leafDER []byte) crypto.Signer {
		if string(leafDER) == "known leaf" {
			return known
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		keyID       string
		certificate []byte
		status      int
		message     string
	}{
		{"known certificate", relayKeyID, certificateMessage([]byte("known leaf")), http.StatusOK, ""},
		{"other key id", "other", certificateMessage([]byte("known leaf")), http.StatusForbidden, "unknown key id"},
		{"unknown certificate", relayKeyID, certificateMessage([]byte("another leaf")), http.StatusForbidden, unknownCertificateMessage},
		{"malformed certificate message", relayKeyID, []byte("not a certificate message"), http.StatusBadRequest, "malformed certificate message"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			hello := []byte("client hello")
			binding := bindings.Issue("lease", hello)
			body, err := json.Marshal(signrpc.TranscriptSignRequest{
				KeyID:               test.keyID,
				Algorithm:           signrpc.AlgorithmECDSASHA256,
				Binding:             binding[:],
				ClientHello:         hello,
				ServerHello:         []byte("server hello"),
				EncryptedExtensions: []byte("encrypted extensions"),
				Certificate:         test.certificate,
				TimestampUnix:       time.Now().Unix(),
				Nonce:               "nonce",
			})
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
			signer.ServeHTTP(recorder, request, "lease")
			if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), test.message) {
				t.Fatalf("sign answer = %d %q, want %d containing %q", recorder.Code, recorder.Body.String(), test.status, test.message)
			}
		})
	}
}

// A renewal can come from another issuer than the pinned chain. The relay still
// holds the key of the pinned certificate, but its API certificate no longer
// verifies against the chain the signer trusts, so the handshake that finds out
// is lost. A client that checks the relay chain on that failure recovers: the
// next handshake presents the new chain. A client that never refreshes is not
// expected to recover from this until it is created again, and nothing here
// asserts that it fails.
func TestClientRepinsWhenARenewalComesFromAnotherIssuer(t *testing.T) {
	t.Parallel()

	pinnedIssuer, otherIssuer := newTestIssuer(t), newTestIssuer(t)
	before, renewed := pinnedIssuer.issue(t, 2), otherIssuer.issue(t, 3)
	relay := newRelayStandIn(t, before)
	client := relay.newClient(t)
	visitors := x509.NewCertPool()
	visitors.AddCert(pinnedIssuer.cert)
	visitors.AddCert(otherIssuer.cert)

	relay.renew(renewed, false)

	_, _ = relay.visit(t, client, visitors) // lost whether or not the signer connection verifies
	if leaf, err := relay.visit(t, client, visitors); err != nil || !leaf.Equal(renewed.leaf) {
		t.Fatalf("handshake after the relay chain was checked: leaf %v, error %v; want the new certificate and no error", leaf, err)
	}
}

// The handshakes of one burst that fail on the same stale pin must share one
// check of the relay chain, so that a relay in trouble is not asked once per
// handshake. A check made on a schedule is not shared.
func TestStaleChainChecksOfOneBurstShareOneFetch(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	first, second, third := issuer.issue(t, 2), issuer.issue(t, 3), issuer.issue(t, 4)
	relay := newRelayStandIn(t, first)
	client := relay.newClient(t)
	seenByTheBurst := client.checks.Load()
	pinnedChain := func(leaf *x509.Certificate) *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		pool.AddCert(issuer.cert)
		return pool
	}
	ctx := context.Background()

	relay.renew(second, false)
	if changed, err := client.refreshChain(ctx, &seenByTheBurst); err != nil || !changed {
		t.Fatalf("first check of the burst = %v, %v; want the new chain pinned", changed, err)
	}
	relay.renew(third, false)
	if changed, err := client.refreshChain(ctx, &seenByTheBurst); err != nil || changed {
		t.Fatalf("later check of the same burst = %v, %v; want it to share the first check", changed, err)
	}
	if !client.RelayCertPool().Equal(pinnedChain(second.leaf)) {
		t.Fatal("a check of the same burst fetched the relay chain again")
	}
	if changed, err := client.RefreshChain(ctx); err != nil || !changed {
		t.Fatalf("scheduled check = %v, %v; want the newest chain pinned", changed, err)
	}
}

// The chain a tenant pins is the one it presents under its own hostname, so a
// chain that does not cover it is never pinned, whatever the relay serves.
func TestRefreshChainKeepsThePinOfAChainThatDoesNotCoverTheHostname(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t)
	before, other := issuer.issue(t, 2), issuer.issueFor(t, 3, "other.test.example")
	relay := newRelayStandIn(t, before)
	client := relay.newClient(t)

	relay.renew(other, false)

	if changed, err := client.RefreshChain(context.Background()); err == nil || changed || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("RefreshChain() = %v, %v; want the chain refused", changed, err)
	}
	if leaf, err := relay.visit(t, client, issuer.pool); err != nil || !leaf.Equal(before.leaf) {
		t.Fatalf("tenant after a refused refresh: leaf %v, error %v; want the pinned certificate and no error", leaf, err)
	}
}

func TestPresentedLeaf(t *testing.T) {
	t.Parallel()

	valid := certificateMessage([]byte("leaf"), []byte("intermediate"))
	if leaf, err := presentedLeaf(valid); err != nil || string(leaf) != "leaf" {
		t.Fatalf("presentedLeaf(valid) = %q, %v; want the first certificate", leaf, err)
	}
	wrongType := append([]byte{handshakeTypeCertificate + 1}, valid[1:]...)
	for name, input := range map[string][]byte{
		"empty":         nil,
		"wrong type":    wrongType,
		"truncated":     valid[:len(valid)-1],
		"trailing data": append(append([]byte{}, valid...), 0),
		"no entries":    certificateMessage(),
		"empty leaf":    certificateMessage(nil),
	} {
		if leaf, err := presentedLeaf(input); err == nil {
			t.Errorf("presentedLeaf(%s) = %q, want an error", name, leaf)
		}
	}
}
