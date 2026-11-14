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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFetchEndpointCertificateChainHonorsProxyEnvironment protects the chain
// fetch's proxy contract: public endpoints follow the proxy environment the
// REST client uses, while local relay hosts always dial directly.
//
// The proxied case runs in a subprocess because net/http caches the proxy
// environment and crypto/x509 the system roots once per process: t.Setenv
// restores the variables but not those caches, so an in-process run would
// depend on execution order and break under -count>1. The child starts with
// clean caches whatever this binary has run before, and the parent asserts
// only its result. The local cases need no isolation: the local exemption
// never consults the proxy rule, and their handshakes skip verification.
func TestFetchEndpointCertificateChainHonorsProxyEnvironment(t *testing.T) {
	if os.Getenv(chainFetchRunEnv) == "1" {
		chainFetchSubprocess(t)
		return
	}
	endpoint := newEndpointTLSServer(t)
	proxy := newConnectProxyStub(t)

	t.Run("direct local relay endpoints", func(t *testing.T) {
		endpointURLs := []string{endpoint.LocalhostURL()}
		// OS resolvers do not universally synthesize *.localhost names —
		// Windows resolves them only through some DNS configurations, and a
		// search-domain or NXDOMAIN-hijacking resolver can even answer with
		// a stranger — so cover the *.localhost shape of the local exemption
		// only where the resolver answers loopback, and never dial the name
		// otherwise.
		if addrs, lookupErr := net.LookupHost("relay.localhost"); lookupErr != nil {
			t.Logf("OS resolver does not synthesize *.localhost (%v); covering bare localhost only", lookupErr)
		} else if !allLoopback(addrs) {
			t.Logf("relay.localhost resolved to non-loopback %v; covering bare localhost only", addrs)
		} else {
			endpointURLs = append(endpointURLs, endpoint.RelayLocalhostURL())
		}
		for _, endpointURL := range endpointURLs {
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
		resultPath := filepath.Join(t.TempDir(), "chain.pem")
		runCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(runCtx, os.Args[0], "-test.run=^TestFetchEndpointCertificateChainHonorsProxyEnvironment$")
		cmd.Env = chainFetchSubprocessEnv(endpoint.PublicURL(), proxy.URL, endpoint.CAPEMPath(t), resultPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("subprocess chain fetch failed: %v\n%s", err, output)
		}
		chainPEM, err := os.ReadFile(resultPath)
		if err != nil {
			t.Fatalf("subprocess wrote no chain (%v):\n%s", err, output)
		}
		assertChainIsEndpointLeaf(t, endpoint, chainPEM)
		if got := proxy.ConnectTargets(); len(got) != 1 || got[0] != endpoint.ConnectTarget() {
			t.Fatalf("proxy CONNECT targets = %v, want [%s]", got, endpoint.ConnectTarget())
		}
	})
}

// chainFetchSubprocessEnv builds a child environment that carries only the
// proxy and trust variables this scenario owns.
func chainFetchSubprocessEnv(endpointURL, proxyURL, caPath, resultPath string) []string {
	env := []string{
		chainFetchRunEnv + "=1",
		chainFetchEndpointEnv + "=" + endpointURL,
		chainFetchResultEnv + "=" + resultPath,
		"HTTPS_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"NO_PROXY=",
		"no_proxy=",
		"SSL_CERT_FILE=" + caPath,
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case chainFetchRunEnv, chainFetchEndpointEnv, chainFetchResultEnv,
			"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
			"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE":
			continue
		}
		env = append(env, entry)
	}
	return env
}

// chainFetchSubprocess runs the real proxied fetch in the child process and
// reports the chain back through the result file.
func chainFetchSubprocess(t *testing.T) {
	fetchCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	chainPEM, err := FetchEndpointCertificateChain(fetchCtx, os.Getenv(chainFetchEndpointEnv), "")
	if err != nil {
		t.Fatalf("FetchEndpointCertificateChain() error = %v", err)
	}
	if err := os.WriteFile(os.Getenv(chainFetchResultEnv), chainPEM, 0o600); err != nil {
		t.Fatalf("write fetched chain: %v", err)
	}
}

const (
	chainFetchRunEnv      = "PORTAL_TEST_CHAIN_FETCH_RUN"
	chainFetchEndpointEnv = "PORTAL_TEST_CHAIN_FETCH_ENDPOINT"
	chainFetchResultEnv   = "PORTAL_TEST_CHAIN_FETCH_RESULT"
)

func allLoopback(addrs []string) bool {
	for _, addr := range addrs {
		if !IsLoopbackHost(addr) {
			return false
		}
	}
	return true
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
