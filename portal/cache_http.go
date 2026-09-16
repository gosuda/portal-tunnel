package portal

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) handleStaticCache(w http.ResponseWriter, req *http.Request) {
	c := s.registry.cache
	if c == nil {
		writeAPIErrorResponse(w, errFeatureUnavailable)
		return
	}
	if req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Authenticate and check origin opt-in before reading an upload body.
	record, err := s.registry.admitLeaseByToken(req.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	s.registry.mu.RLock()
	site := &cachedSite{
		host: record.Hostname, owner: record.Key(), leaseID: record.id,
		clientIP: record.ClientIP, ttl: record.CacheTTL,
		expiresAt: record.cacheExpiresAt(), usedAt: time.Now(),
	}
	allowed := record.Cache && !record.isExpired(time.Now())
	s.registry.mu.RUnlock()
	if !allowed {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	if req.Method == http.MethodDelete {
		c.mu.Lock()
		if existing := c.entries[site.host]; existing != nil && existing.leaseID == site.leaseID {
			c.retireLocked(existing)
		}
		c.mu.Unlock()
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
		return
	}
	select {
	case c.population <- struct{}{}:
		defer func() { <-c.population }()
	default:
		http.Error(w, "relay cache population is busy; use origin tunnel", http.StatusServiceUnavailable)
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Minute))
	defer controller.SetReadDeadline(time.Time{})
	var manifest types.StaticCacheManifest
	var parts *multipart.Reader
	var manifestReader io.Reader = http.MaxBytesReader(w, req.Body, types.StaticCacheManifestLimit)
	if req.Method == http.MethodPut {
		// Includes multipart framing and manifest bytes, with a fixed bound.
		req.Body = http.MaxBytesReader(w, req.Body, int64(c.cfg.MaxExposureBytes)+2*types.StaticCacheManifestLimit)
		parts, err = req.MultipartReader()
		if err == nil {
			var part *multipart.Part
			part, err = parts.NextRawPart()
			if err == nil {
				manifestReader = io.LimitReader(part, types.StaticCacheManifestLimit+1)
			}
		}
	}
	if err == nil {
		var raw []byte
		raw, err = io.ReadAll(manifestReader)
		if err == nil && len(raw) > types.StaticCacheManifestLimit {
			err = errors.New("cache manifest is too large")
		}
		if err == nil {
			err = json.Unmarshal(raw, &manifest)
		}
	}
	if err == nil {
		site.digest, site.bytes, err = utils.StaticCacheDigest(manifest, int64(c.cfg.MaxObjectSize), int64(c.cfg.MaxExposureBytes))
	}
	if err != nil {
		utils.InvalidRequestError(err).Write(w)
		return
	}
	if req.Method == http.MethodPost {
		c.mu.Lock()
		existing := c.entries[site.host]
		status := types.StaticCacheStatus{Present: existing != nil && existing.leaseID == site.leaseID && existing.digest == site.digest && time.Now().Before(existing.expiresAt)}
		if status.Present {
			status.ExpiresAt = existing.expiresAt
		} else if existing != nil && existing.leaseID == site.leaseID {
			// A changed snapshot falls back to the live origin until its
			// replacement is complete, including when admission later fails.
			c.retireLocked(existing)
		}
		c.mu.Unlock()
		utils.WriteAPIData(w, http.StatusOK, status)
		return
	}
	if err := c.reserve(site.bytes); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	published := false
	defer func() {
		if !published {
			c.mu.Lock()
			c.retired = append(c.retired, site)
			c.mu.Unlock()
			c.collect(time.Now())
		}
	}()
	site.dir, err = os.MkdirTemp(c.cfg.Dir, "portal-cache-")
	if err == nil {
		site.index = manifest.Index
		site.files = make(map[string]types.StaticCacheFile, len(manifest.Files))
		for _, file := range manifest.Files {
			part, partErr := parts.NextRawPart()
			if partErr != nil {
				err = partErr
				break
			}
			// Disk filenames are content hashes, never uploaded paths. Distinct
			// URLs may share a digest within this snapshot.
			output, createErr := os.Create(filepath.Join(site.dir, file.SHA256))
			if createErr != nil {
				err = createErr
				break
			}
			hash := sha256.New()
			_, copyErr := io.CopyN(io.MultiWriter(output, hash), part, file.Size)
			closeErr := output.Close()
			var extra [1]byte
			n, endErr := part.Read(extra[:])
			if copyErr != nil || closeErr != nil || n != 0 || !errors.Is(endErr, io.EOF) || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
				err = errors.New("cache object is truncated, oversized, or has an invalid SHA-256")
				break
			}
			site.files[file.Path] = file
		}
	}
	if err == nil {
		_, endErr := parts.NextRawPart()
		if !errors.Is(endErr, io.EOF) {
			err = errors.New("unexpected cache upload parts")
		}
	}
	if err != nil {
		utils.InvalidRequestError(err).Write(w)
		return
	}
	// Recheck the lease under the replacement lock: a late upload can never
	// publish for a disconnected/replaced origin or re-enable revoked opt-in.
	s.registry.mu.RLock()
	active := s.registry.recordByLease(site.owner, site.leaseID, time.Now())
	var status types.StaticCacheStatus
	if active != nil && active.Cache && s.registry.policy.IsIdentityRoutable(site.owner) && !s.registry.policy.IPFilter().IsIPBanned(active.ClientIP) {
		c.mu.Lock()
		if previous := c.entries[site.host]; previous != nil {
			c.retireLocked(previous)
		}
		site.expiresAt = active.cacheExpiresAt()
		c.entries[site.host] = site
		published = true
		status = types.StaticCacheStatus{Present: true, ExpiresAt: site.expiresAt}
		c.mu.Unlock()
	}
	s.registry.mu.RUnlock()
	if !published {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	c.collect(time.Now())
	utils.WriteAPIData(w, http.StatusOK, status)
}

// Tenant hosts never reach the relay control plane, including on a connection
// with a mismatched Host header. TLS termination here is explicit cache opt-in.
func (s *Server) serveCachedSite(w http.ResponseWriter, req *http.Request, host string) {
	if req.TLS == nil || utils.NormalizeHostname(req.TLS.ServerName) != host {
		http.Error(w, "TLS name and request host must match", http.StatusMisdirectedRequest)
		return
	}
	site := s.registry.acquireCachedSite(host)
	if site != nil {
		defer s.registry.cache.release(site)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			rel, valid := utils.StaticSiteRequestPath("/", req.URL.Path)
			if !valid {
				http.NotFound(w, req)
				return
			}
			file, found := site.files[strings.TrimPrefix(rel, "/")]
			if !found {
				file = site.files[site.index]
			}
			input, err := os.Open(filepath.Join(site.dir, file.SHA256))
			if err == nil {
				defer input.Close()
				w.Header().Set("ETag", `"`+file.SHA256+`"`)
				// Offline retention is relay-owned, not a browser cache lifetime.
				w.Header().Set("Cache-Control", "no-cache")
				http.ServeContent(w, req, file.Path, time.Time{}, input)
				return
			}
		}
	}
	// A snapshot can be evicted between ClientHello routing and HTTP lookup.
	// Reuse the reverse stream for fallback, never dial a user-supplied URL.
	// This already-terminated connection remains within the cache trust opt-in.
	record, ok := s.registry.Lookup(host)
	allowed := false
	if ok {
		s.registry.mu.RLock()
		allowed = record.Cache && !record.isExpired(time.Now()) && s.registry.policy.IsIdentityRoutable(record.Key()) && !s.registry.policy.IPFilter().IsIPBanned(record.ClientIP)
		s.registry.mu.RUnlock()
	}
	if !allowed {
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
