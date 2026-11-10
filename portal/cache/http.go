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

var errCacheManifestIsTooLarge = errors.New("cache manifest is too large")
var errUnexpectedCacheUploadParts = errors.New("unexpected cache upload parts")
var errCacheObjectIsTruncatedOversizedOrInvalid = errors.New("cache object is truncated, oversized, or has an invalid SHA-256")

func (c *Manager) Handle(w http.ResponseWriter, req *http.Request, leaseID string, generation uint64) {
	if c.rejectUnhandledCacheRequest(w, req) {
		return
	}
	c.mu.Lock()
	lease := c.leases[leaseID]
	allowed := c.eligibleLocked(leaseID) && lease.generation == generation
	c.mu.Unlock()
	if !allowed {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
		return
	}
	site := &cachedSite{host: lease.Hostname, owner: lease.Owner, leaseID: lease.ID, ttl: lease.ttl, expiresAt: lease.cacheExpiry(), usedAt: time.Now()}
	if req.Method == http.MethodDelete {
		c.mu.Lock()
		if existing := c.entries[site.host]; existing != nil && existing.leaseID == site.leaseID && c.eligibleLocked(site.leaseID) && c.leases[site.leaseID].generation == generation {
			c.retireLocked(existing)
		}
		c.mu.Unlock()
		utils.WriteAPIData(w, http.StatusOK, types.StaticCacheStatus{})
		return
	}
	readTimeout, release, ok := c.admitHandleRequestSlot(w, req, site.owner)
	if !ok {
		return
	}
	defer release()
	controller, parts, manifest, err := c.decodeUploadManifest(req, w, readTimeout, site)
	if err != nil {
		utils.InvalidRequestError(err).Write(w)
		return
	}
	defer resetHandleReadDeadline(controller, &err)
	if c.serveHandlePostCacheRequest(w, req, site, generation) {
		return
	}
	if err := c.reserve(site.bytes); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	published := false
	defer func() {
		if !published {
			c.retireHandleUnpublished(site)
		}
	}()
	if stageErr := stageUpload(site, parts, manifest, c.dir); stageErr != nil {
		err = stageErr
		utils.InvalidRequestError(err).Write(w)
		return
	}
	c.mu.Lock()
	uploadStatus, published := c.publishStagedLocked(site, generation)
	c.mu.Unlock()
	if !published {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
		return
	}
	c.collect(time.Now())
	utils.WriteAPIData(w, http.StatusOK, uploadStatus)
}

func (c *Manager) admitHandleRequestSlot(w http.ResponseWriter, req *http.Request, owner types.ServiceIdentityKey) (time.Duration, func(), bool) {
	if req.Method == http.MethodPut {
		c.mu.Lock()
		_, active := c.uploads[owner]
		if active || len(c.uploads) >= 2 {
			c.mu.Unlock()
			http.Error(w, "relay cache upload limit reached; use origin tunnel", http.StatusServiceUnavailable)
			return 0, nil, false
		}
		c.uploads[owner] = struct{}{}
		c.mu.Unlock()
		return 2 * time.Minute, func() {
			c.mu.Lock()
			delete(c.uploads, owner)
			c.mu.Unlock()
		}, true
	}
	select {
	case c.checks <- struct{}{}:
		return 10 * time.Second, func() { <-c.checks }, true
	default:
		http.Error(w, "relay cache request limit reached; use origin tunnel", http.StatusServiceUnavailable)
		return 0, nil, false
	}
}

func (c *Manager) serveHandlePostCacheRequest(w http.ResponseWriter, req *http.Request, site *cachedSite, generation uint64) bool {
	if req.Method != http.MethodPost {
		return false
	}
	c.mu.Lock()
	if !c.eligibleLocked(site.leaseID) || c.leases[site.leaseID].generation != generation {
		c.mu.Unlock()
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "cache lease unavailable")
		return true
	}
	status := c.postCacheStatusLocked(site)
	c.mu.Unlock()
	utils.WriteAPIData(w, http.StatusOK, status)
	return true
}

func resetHandleReadDeadline(controller *http.ResponseController, err *error) {
	if *err == nil {
		_ = controller.SetReadDeadline(time.Time{})
	}
}

func (c *Manager) retireHandleUnpublished(site *cachedSite) {
	c.mu.Lock()
	c.retired = append(c.retired, site)
	c.mu.Unlock()
	c.collect(time.Now())
}

func (c *Manager) rejectUnhandledCacheRequest(w http.ResponseWriter, req *http.Request) bool {
	if c == nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "cache unavailable")
		return true
	}
	if req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodDelete {
		w.Header().Set("Allow", "POST, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	return false
}

func (c *Manager) postCacheStatusLocked(site *cachedSite) types.StaticCacheStatus {
	existing := c.entries[site.host]
	status := types.StaticCacheStatus{Present: existing != nil && existing.leaseID == site.leaseID && existing.digest == site.digest && time.Now().Before(existing.expiresAt)}
	if status.Present {
		status.ExpiresAt = existing.expiresAt
	} else if existing != nil && existing.leaseID == site.leaseID {
		c.retireLocked(existing)
	}
	return status
}

func (c *Manager) decodeUploadManifest(req *http.Request, w http.ResponseWriter, readTimeout time.Duration, site *cachedSite) (*http.ResponseController, *multipart.Reader, types.StaticCacheManifest, error) {
	var manifest types.StaticCacheManifest
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(readTimeout)
	_ = controller.SetReadDeadline(deadline)
	parts, manifestReader, err := c.openUploadParts(req, w, controller, deadline)
	if err != nil {
		return nil, nil, manifest, err
	}
	manifest, err = parseManifestBody(manifestReader)
	if err != nil {
		return nil, nil, manifest, err
	}
	digest, size, err := manifestDigest(manifest, c.limits.MaxObjectSize, c.limits.MaxExposureBytes)
	if err != nil {
		return nil, nil, manifest, err
	}
	site.digest, site.bytes = digest, size
	return controller, parts, manifest, nil
}

func (c *Manager) publishStagedLocked(site *cachedSite, generation uint64) (types.StaticCacheStatus, bool) {
	if !c.eligibleLocked(site.leaseID) || c.leases[site.leaseID].generation != generation {
		return types.StaticCacheStatus{}, false
	}
	live := c.leases[site.leaseID]
	if previous := c.entries[site.host]; previous != nil {
		c.retireLocked(previous)
	}
	site.expiresAt = live.cacheExpiry()
	c.entries[site.host] = site
	return types.StaticCacheStatus{Present: true, ExpiresAt: site.expiresAt}, true
}

func (c *Manager) openUploadParts(req *http.Request, w http.ResponseWriter, controller *http.ResponseController, deadline time.Time) (*multipart.Reader, io.Reader, error) {
	if req.Method != http.MethodPut {
		return nil, http.MaxBytesReader(w, req.Body, types.StaticCacheManifestLimit), nil
	}
	req.Body = &idleUploadBody{
		ReadCloser:  http.MaxBytesReader(w, req.Body, c.limits.MaxExposureBytes+2*types.StaticCacheManifestLimit),
		controller:  controller,
		maxDeadline: deadline,
	}
	parts, err := req.MultipartReader()
	if err != nil {
		return nil, nil, err
	}
	part, err := parts.NextRawPart()
	if err != nil {
		return nil, nil, err
	}
	return parts, io.LimitReader(part, types.StaticCacheManifestLimit+1), nil
}

func parseManifestBody(manifestReader io.Reader) (types.StaticCacheManifest, error) {
	var manifest types.StaticCacheManifest
	raw, err := io.ReadAll(manifestReader)
	if err != nil {
		return manifest, err
	}
	if len(raw) > types.StaticCacheManifestLimit {
		return manifest, errCacheManifestIsTooLarge
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func stageUpload(site *cachedSite, parts *multipart.Reader, manifest types.StaticCacheManifest, dir string) error {
	staged, err := os.MkdirTemp(dir, "portal-cache-")
	if err != nil {
		return err
	}
	site.dir = staged
	root, err := os.OpenRoot(site.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	site.index = manifest.Index
	site.files = make(map[string]types.StaticCacheFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := stageUploadObject(root, parts, site, file); err != nil {
			return err
		}
	}
	if _, err := parts.NextRawPart(); !errors.Is(err, io.EOF) {
		return errUnexpectedCacheUploadParts
	}
	return nil
}

func stageUploadObject(root *os.Root, parts *multipart.Reader, site *cachedSite, file types.StaticCacheFile) error {
	part, err := parts.NextRawPart()
	if err != nil {
		return err
	}
	output, err := root.Create(file.SHA256)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.CopyN(io.MultiWriter(output, hash), part, file.Size)
	closeErr := output.Close()
	var extra [1]byte
	n, endErr := part.Read(extra[:])
	if copyErr != nil || closeErr != nil || n != 0 || !errors.Is(endErr, io.EOF) || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return errCacheObjectIsTruncatedOversizedOrInvalid
	}
	site.files[file.Path] = file
	return nil
}

const uploadIdleTimeout = 10 * time.Second

type idleUploadBody struct {
	io.ReadCloser
	controller  *http.ResponseController
	maxDeadline time.Time
}

func (b *idleUploadBody) Read(p []byte) (int, error) {
	deadline := time.Now().Add(uploadIdleTimeout)
	if deadline.After(b.maxDeadline) {
		deadline = b.maxDeadline
	}
	if err := b.controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	return b.ReadCloser.Read(p)
}
