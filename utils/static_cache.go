package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// StaticCacheDigest validates the bounded wire manifest and hashes its canonical
// representation. Paths are URL paths, never filesystem extraction targets.
func StaticCacheDigest(m types.StaticCacheManifest, maxObject, maxBytes int64) (string, int64, error) {
	if len(m.Files) == 0 || len(m.Files) > types.StaticCacheMaxFiles {
		return "", 0, errors.New("invalid static cache file count")
	}
	var total int64
	previous := ""
	hasIndex := false
	for _, file := range m.Files {
		if !fs.ValidPath(file.Path) || file.Path == "." || len(file.Path) > 2048 || strings.ContainsAny(file.Path, "\\\x00\r\n") || file.Path <= previous {
			return "", 0, errors.New("cache file paths must be safe, unique, and sorted")
		}
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != sha256.Size || file.SHA256 != strings.ToLower(file.SHA256) {
			return "", 0, errors.New("invalid cache file SHA-256")
		}
		if file.Size < 0 || file.Size > maxObject || file.Size > maxBytes-total {
			return "", 0, errors.New("static cache snapshot exceeds relay limits")
		}
		total += file.Size
		previous = file.Path
		hasIndex = hasIndex || file.Path == m.Index
	}
	if !hasIndex {
		return "", 0, errors.New("static cache snapshot is missing its entry file")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", 0, err
	}
	if len(raw) > types.StaticCacheManifestLimit {
		return "", 0, errors.New("static cache manifest is too large")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), total, nil
}
