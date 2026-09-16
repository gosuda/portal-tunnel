package portal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// cacheLease copies registry facts while the caller holds the registry lock.
func (r *leaseRecord) cacheLease() cache.Lease {
	return cache.Lease{ID: r.id, Owner: r.Key(), Hostname: r.Hostname, HostnameHash: r.HostnameHash, ClientIP: r.ClientIP, ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt}
}

func (s *Server) handleStaticCache(w http.ResponseWriter, req *http.Request) {
	record, err := s.registry.admitLeaseByToken(req.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	s.registry.cache.Handle(w, req, record.id)
}

// Tenant hosts never reach the relay control plane, including on a connection
// with a mismatched Host header. TLS termination here is explicit cache opt-in.
func (s *Server) serveCachedSite(w http.ResponseWriter, req *http.Request, host string) {
	if req.TLS == nil || utils.NormalizeHostname(req.TLS.ServerName) != host {
		http.Error(w, "TLS name and request host must match", http.StatusMisdirectedRequest)
		return
	}
	if s.registry.cache.Serve(w, req, host) {
		return
	}
	// A snapshot can be evicted between ClientHello routing and HTTP lookup.
	// Reuse the reverse stream for fallback, never dial a user-supplied URL.
	// This already-terminated connection remains within the cache trust opt-in.
	record, ok := s.registry.Lookup(host)
	if !ok || !s.registry.cache.Eligible(record.id) {
		http.Error(w, "static origin unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			upstream, err := record.stream.Claim(ctx)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			for _, cert := range s.apiServer.TLSConfig.Certificates {
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					_ = upstream.Close()
					return nil, err
				}
				roots.AddCert(leaf)
			}
			conn := tls.Client(upstream, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("cache fallback TLS: %w", err)
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "https", Host: host})
	proxy.Transport = transport
	proxy.ServeHTTP(w, req.WithContext(ctx))
}
