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
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// TestFetchEndpointCertificateChainHonorsProxyEnvironment protects the chain
// fetch's proxy contract: public endpoints follow the REST client's proxy
// rule, while local relay hosts always dial directly.
//
// The rule is injected through endpointProxy because http.ProxyFromEnvironment
// reads the environment only once per process, so a t.Setenv proxy would go
// stale on -count=2 or after any earlier proxied dial in this binary.
func TestFetchEndpointCertificateChainHonorsProxyEnvironment(t *testing.T) {
	endpoint := newEndpointTLSServer(t)
	proxy := newConnectProxyStub(t)
	proxyFunc := (&httpproxy.Config{HTTPProxy: proxy.URL, HTTPSProxy: proxy.URL}).ProxyFunc()
	var proxyLookups sync.Map
	previous := endpointProxy
	endpointProxy = func(request *http.Request) (*url.URL, error) {
		proxyLookups.Store(request.URL.Host, true)
		return proxyFunc(request.URL)
	}
	t.Cleanup(func() { endpointProxy = previous })

	t.Run("direct local relay endpoints", func(t *testing.T) {
		chainPEM, err := FetchEndpointCertificateChain(context.Background(), endpoint.LocalhostURL(), "")
		if err != nil {
			t.Fatalf("FetchEndpointCertificateChain() error = %v", err)
		}
		assertChainIsEndpointLeaf(t, endpoint, chainPEM)
		// *.localhost names need not resolve (Windows, minimal resolvers), so
		// only the routing decision is asserted: the dial outcome is ignored.
		relayHost, relayPort, err := net.SplitHostPort(endpoint.RelayLocalhostAddress())
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := dialEndpointTCP(context.Background(), relayHost, relayPort); err == nil {
			_ = conn.Close()
		}
		proxyLookups.Range(func(host, _ any) bool {
			t.Errorf("local relay host %v consulted the proxy rule", host)
			return true
		})
		if got := proxy.ConnectTargets(); len(got) != 0 {
			t.Fatalf("local relay fetch dialed %v through the proxy, want none: the chain pins the dialed peer's trust, so a proxy in between would define it", got)
		}
	})

	// The public case stops at dialEndpointTCP and verifies the tunneled
	// handshake against the endpoint root itself: the system roots load once
	// per process, so SSL_CERT_FILE cannot plant this root reliably.
	t.Run("proxied public endpoint", func(t *testing.T) {
		host, port, err := net.SplitHostPort(endpoint.ConnectTarget())
		if err != nil {
			t.Fatal(err)
		}
		rawConn, err := dialEndpointTCP(context.Background(), host, port)
		if err != nil {
			t.Fatalf("dialEndpointTCP() error = %v", err)
		}
		defer rawConn.Close()
		roots := x509.NewCertPool()
		roots.AddCert(endpoint.leaf)
		tlsConn := tls.Client(rawConn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots})
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("verified handshake through the proxy tunnel error = %v", err)
		}
		if peers := tlsConn.ConnectionState().PeerCertificates; len(peers) == 0 || !peers[0].Equal(endpoint.leaf) {
			t.Fatal("tunneled peer certificate does not match the endpoint certificate")
		}
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
}

func (s *endpointTLSServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *endpointTLSServer) LocalhostURL() string {
	return fmt.Sprintf("https://localhost:%d", s.port())
}

// RelayLocalhostAddress names the listener with a *.localhost host: a local relay
// trust host that proxy resolution would otherwise route through a proxy.
func (s *endpointTLSServer) RelayLocalhostAddress() string {
	return fmt.Sprintf("relay.localhost:%d", s.port())
}

// ConnectTarget names the listener with a host neither local trust nor proxy
// exemption covers, the way a public relay endpoint looks.
func (s *endpointTLSServer) ConnectTarget() string {
	return fmt.Sprintf("relay.test.example:%d", s.port())
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
	server := &endpointTLSServer{listener: listener, leaf: leaf}
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
