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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// http.ProxyFromEnvironment snapshots the proxy environment once per process,
// so the proxy variables are set before the first endpoint dial in this test
// binary. The direct case stays valid under any snapshot because Go never
// proxies loopback addresses.
func TestFetchEndpointCertificateChainHonorsProxyEnvironment(t *testing.T) {
	endpoint := newEndpointTLSServer(t)
	proxy := newConnectProxyStub(t)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	t.Run("direct loopback endpoint", func(t *testing.T) {
		chainPEM, err := FetchEndpointCertificateChain(context.Background(), endpoint.LocalhostURL(), "")
		if err != nil {
			t.Fatalf("FetchEndpointCertificateChain() error = %v", err)
		}
		assertChainIsEndpointLeaf(t, endpoint, chainPEM)
		if got := proxy.ConnectTargets(); len(got) != 0 {
			t.Fatalf("loopback fetch dialed %v through the proxy, want none", got)
		}
	})

	t.Run("proxied endpoint", func(t *testing.T) {
		chainPEM, err := FetchEndpointCertificateChain(context.Background(), endpoint.RelayLocalhostURL(), "")
		if err != nil {
			t.Fatalf("FetchEndpointCertificateChain() error = %v", err)
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
}

func (s *endpointTLSServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *endpointTLSServer) LocalhostURL() string {
	return fmt.Sprintf("https://localhost:%d", s.port())
}

// RelayLocalhostURL names the same listener with a host that proxy resolution
// treats as proxiable while endpoint TLS trust still covers it.
func (s *endpointTLSServer) RelayLocalhostURL() string {
	return fmt.Sprintf("https://relay.localhost:%d", s.port())
}

func (s *endpointTLSServer) ConnectTarget() string {
	return fmt.Sprintf("relay.localhost:%d", s.port())
}

func newEndpointTLSServer(t *testing.T) *endpointTLSServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay endpoint"},
		DNSNames:     []string{"localhost", "relay.localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
