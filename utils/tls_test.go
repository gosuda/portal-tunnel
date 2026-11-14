package utils

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestFetchEndpointCertificateChainHonorsProxyEnvironment protects the chain
// fetch's proxy contract: public endpoints follow the proxy environment the
// REST client uses, while local relay hosts always dial directly.
//
// net/http snapshots the proxy environment once per process and crypto/x509
// loads the system roots once per process, so the proxy variables are set
// here before the first endpoint dial and the proxied case plants its trust
// root through SSL_CERT_FILE before the first verified handshake. Any earlier
// test in this binary that issues a real request through a proxy-configured
// transport, or performs a verified TLS handshake, would break this ordering;
// the probe below turns that into an immediate, explained failure.
func TestFetchEndpointCertificateChainHonorsProxyEnvironment(t *testing.T) {
	endpoint := newEndpointTLSServer(t)
	proxy := newConnectProxyStub(t)
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	probeURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "snapshot-probe.invalid:1"}})
	if err != nil || resolved == nil || resolved.String() != probeURL.String() {
		t.Fatalf("proxy environment snapshot predates this test (net/http caches it once per process): resolved %v, err %v; an earlier test must have issued a request through a proxy-configured transport", resolved, err)
	}

	t.Run("direct local relay endpoints", func(t *testing.T) {
		for _, endpointURL := range []string{endpoint.LocalhostURL(), endpoint.RelayLocalhostURL()} {
			chainPEM, err := FetchEndpointCertificateChain(context.Background(), endpointURL, "")
			if err != nil {
				t.Fatalf("FetchEndpointCertificateChain(%q) error = %v", endpointURL, err)
			}
			assertChainIsEndpointLeaf(t, endpoint, chainPEM)
		}
		if got := proxy.ConnectTargets(); len(got) != 0 {
			t.Fatalf("local relay fetch dialed %v through the proxy, want none: the chain pins the dialed peer's trust, so a proxy in between would define it", got)
		}
	})

	t.Run("proxied public endpoint", func(t *testing.T) {
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			t.Skipf("%s ignores SSL_CERT_FILE, so the system-root injection this case needs is unavailable", runtime.GOOS)
		}
		t.Setenv("SSL_CERT_FILE", endpoint.CAPEMPath(t))
		chainPEM, err := FetchEndpointCertificateChain(context.Background(), endpoint.PublicURL(), "")
		if err != nil {
			t.Fatalf("FetchEndpointCertificateChain() error = %v (the system-root snapshot may predate this test's SSL_CERT_FILE)", err)
		}
		assertChainIsEndpointLeaf(t, endpoint, chainPEM)
		if got := proxy.ConnectTargets(); len(got) != 1 || got[0] != endpoint.ConnectTarget() {
			t.Fatalf("proxy CONNECT targets = %v, want [%s]", got, endpoint.ConnectTarget())
		}
	})
}

func assertChainIsEndpointLeaf(t *testing.T, endpoint *endpointTLSServer, chainPEM []byte) {
	t.Helper()
	leaf, err := ParseCertificatePEM(chainPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM() error = %v", err)
	}
	if !leaf.Equal(endpoint.leaf) {
		t.Fatal("fetched chain does not match the endpoint certificate")
	}
}

type endpointTLSServer struct {
	listener net.Listener
	leaf     *x509.Certificate
	certPEM  []byte
}

func (s *endpointTLSServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *endpointTLSServer) LocalhostURL() string {
	return fmt.Sprintf("https://localhost:%d", s.port())
}

// RelayLocalhostURL names the listener with a *.localhost host: a local relay
// trust host that proxy resolution would otherwise route through a proxy.
func (s *endpointTLSServer) RelayLocalhostURL() string {
	return fmt.Sprintf("https://relay.localhost:%d", s.port())
}

// PublicURL names the listener with a host neither local trust nor proxy
// exemption covers, the way a public relay endpoint looks.
func (s *endpointTLSServer) PublicURL() string {
	return fmt.Sprintf("https://relay.test.example:%d", s.port())
}

func (s *endpointTLSServer) ConnectTarget() string {
	return fmt.Sprintf("relay.test.example:%d", s.port())
}

// CAPEMPath writes the endpoint certificate for SSL_CERT_FILE so the proxied
// fetch verifies it with the ordinary system-root path.
func (s *endpointTLSServer) CAPEMPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endpoint-ca.pem")
	if err := os.WriteFile(path, s.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newEndpointTLSServer(t *testing.T) *endpointTLSServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay endpoint"},
		DNSNames:              []string{"localhost", "relay.localhost", "relay.test.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER(t, key)}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &endpointTLSServer{listener: listener, leaf: leaf, certPEM: certPEM}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()
	return server
}

func privateKeyDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type connectProxyStub struct {
	URL string

	mu      sync.Mutex
	targets []string
}

func (p *connectProxyStub) ConnectTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// newConnectProxyStub answers CONNECT by tunneling to the endpoint port on
// loopback, whatever host the client asked for.
func newConnectProxyStub(t *testing.T) *connectProxyStub {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stub := &connectProxyStub{URL: fmt.Sprintf("http://%s", listener.Addr())}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go stub.tunnel(conn)
		}
	}()
	return stub
}

func (p *connectProxyStub) tunnel(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	if request.Method != http.MethodConnect {
		_, _ = conn.Write([]byte("HTTP/1.1 405 method not allowed\r\n\r\n"))
		return
	}
	_, port, err := net.SplitHostPort(request.Host)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 400 bad request\r\n\r\n"))
		return
	}
	endpoint, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 bad gateway\r\n\r\n"))
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 connection established\r\n\r\n")); err != nil {
		_ = endpoint.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	p.mu.Lock()
	p.targets = append(p.targets, request.Host)
	p.mu.Unlock()
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(endpoint, conn)
		_ = endpoint.Close()
		close(copied)
	}()
	_, _ = io.Copy(conn, endpoint)
	_ = conn.Close()
	<-copied
}
