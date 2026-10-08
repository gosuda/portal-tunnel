package types

import "time"

const (
	StaticCacheMaxFiles      = 2048
	StaticCacheManifestLimit = 1 << 20
)

// StaticCacheManifest describes a complete immutable snapshot, including the
// SPA entry. Multipart uploads carry these files in manifest order.
type StaticCacheManifest struct {
	Index string            `json:"index"`
	Files []StaticCacheFile `json:"files"`
}

type StaticCacheFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type StaticCacheStatus struct {
	Present   bool      `json:"present"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type StaticCacheLimits struct {
	MaxExposureBytes int64 `json:"max_exposure_bytes"`
	MaxObjectSize    int64 `json:"max_object_size"`
}
