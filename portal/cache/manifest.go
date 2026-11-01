package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errInvalidStaticCacheFileCount           = errors.New("invalid static cache file count")
	errCacheFilePathsMustSafeUnique          = errors.New("cache file paths must be safe, unique, and sorted")
	errInvalidCacheFileSha256                = errors.New("invalid cache file SHA-256")
	errStaticCacheSnapshotExceedsRelayLimits = errors.New("static cache snapshot exceeds relay limits")
	errStaticCacheSnapshotMissingItsEntry    = errors.New("static cache snapshot is missing its entry file")
	errStaticCacheManifestTooLarge           = errors.New("static cache manifest is too large")
)

// manifestDigest validates the bounded wire manifest and hashes its canonical
// representation. Paths are URL paths, never filesystem extraction targets.
func manifestDigest(m types.StaticCacheManifest, maxObject, maxBytes int64) (string, int64, error) {
	if len(m.Files) == 0 || len(m.Files) > types.StaticCacheMaxFiles {
		return "", 0, errInvalidStaticCacheFileCount
	}
	var total int64
	previous := ""
	hasIndex := false
	for _, file := range m.Files {
		if !fs.ValidPath(file.Path) || file.Path == "." || len(file.Path) > 2048 || strings.ContainsAny(file.Path, "\\\x00\r\n") || file.Path <= previous {
			return "", 0, errCacheFilePathsMustSafeUnique
		}
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != sha256.Size || file.SHA256 != strings.ToLower(file.SHA256) {
			return "", 0, errInvalidCacheFileSha256
		}
		if file.Size < 0 || file.Size > maxObject || file.Size > maxBytes-total {
			return "", 0, errStaticCacheSnapshotExceedsRelayLimits
		}
		total += file.Size
		previous = file.Path
		hasIndex = hasIndex || file.Path == m.Index
	}
	if !hasIndex {
		return "", 0, errStaticCacheSnapshotMissingItsEntry
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", 0, err
	}
	if len(raw) > types.StaticCacheManifestLimit {
		return "", 0, errStaticCacheManifestTooLarge
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), total, nil
}
