package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (c *Manager) Handle(w http.ResponseWriter, req *http.Request, leaseID string) {
	if c == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "cache unavailable")
		return
	}
	if req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	lease := c.leases[leaseID]
	allowed := c.eligibleLocked(leaseID)
	c.mu.Unlock()
	if !allowed {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
		return
	}
	site := &cachedSite{host: lease.Hostname, owner: lease.Owner, leaseID: lease.ID, ttl: lease.ttl, expiresAt: lease.cacheExpiry(), usedAt: time.Now()}
	if req.Method == http.MethodDelete {
		c.mu.Lock()
		if existing := c.entries[site.host]; existing != nil && existing.leaseID == site.leaseID && c.eligibleLocked(site.leaseID) {
			c.retireLocked(existing)
		}
		c.mu.Unlock()
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
		return
	}
	// Manifest checks cannot consume upload slots, but still have their own
	// bounded concurrency, body size, and shorter read deadline.
	slots, readTimeout := c.population, 2*time.Minute
	if req.Method == http.MethodPost {
		slots, readTimeout = c.checks, 10*time.Second
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		http.Error(w, "relay cache request limit reached; use origin tunnel", http.StatusServiceUnavailable)
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(readTimeout))
	defer controller.SetReadDeadline(time.Time{})
	var manifest types.StaticCacheManifest
	var err error
	var parts *multipart.Reader
	var manifestReader io.Reader = http.MaxBytesReader(w, req.Body, types.StaticCacheManifestLimit)
	if req.Method == http.MethodPut {
		// Includes multipart framing and manifest bytes, with a fixed bound.
		req.Body = http.MaxBytesReader(w, req.Body, c.limits.MaxExposureBytes+2*types.StaticCacheManifestLimit)
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
		site.digest, site.bytes, err = manifestDigest(manifest, c.limits.MaxObjectSize, c.limits.MaxExposureBytes)
	}
	if err != nil {
		utils.InvalidRequestError(err).Write(w)
		return
	}
	if req.Method == http.MethodPost {
		c.mu.Lock()
		if !c.eligibleLocked(site.leaseID) {
			c.mu.Unlock()
			utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
			return
		}
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
	site.dir, err = os.MkdirTemp(c.dir, "portal-cache-")
	var root *os.Root
	if err == nil {
		root, err = os.OpenRoot(site.dir)
	}
	if err == nil {
		defer root.Close()
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
			output, createErr := root.Create(file.SHA256)
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
	c.mu.Lock()
	var status types.StaticCacheStatus
	if c.eligibleLocked(site.leaseID) {
		active := c.leases[site.leaseID]
		if previous := c.entries[site.host]; previous != nil {
			c.retireLocked(previous)
		}
		site.expiresAt = active.cacheExpiry()
		c.entries[site.host] = site
		published = true
		status = types.StaticCacheStatus{Present: true, ExpiresAt: site.expiresAt}
	}
	c.mu.Unlock()
	if !published {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
		return
	}
	c.collect(time.Now())
	utils.WriteAPIData(w, http.StatusOK, status)
}
