package cache

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestManifestDigestRejectsInvalidEntries(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	tooMany := make([]types.StaticCacheFile, types.StaticCacheMaxFiles+1)
	for i := range tooMany {
		tooMany[i] = types.StaticCacheFile{Path: fmt.Sprintf("%08d", i), SHA256: validHash}
	}
	tests := map[string]types.StaticCacheManifest{
		"too many files": {Index: tooMany[0].Path, Files: tooMany},
		"duplicate path": {Index: "a.html", Files: []types.StaticCacheFile{
			{Path: "a.html", Size: 1, SHA256: validHash},
			{Path: "a.html", Size: 1, SHA256: validHash},
		}},
		"unsorted paths": {Index: "a.html", Files: []types.StaticCacheFile{
			{Path: "b.html", Size: 1, SHA256: validHash},
			{Path: "a.html", Size: 1, SHA256: validHash},
		}},
		"negative size": {Index: "index.html", Files: []types.StaticCacheFile{
			{Path: "index.html", Size: -1, SHA256: validHash},
		}},
		"sha256 not hex": {Index: "index.html", Files: []types.StaticCacheFile{
			{Path: "index.html", Size: 1, SHA256: strings.Repeat("z", 64)},
		}},
		"sha256 wrong byte length": {Index: "index.html", Files: []types.StaticCacheFile{
			{Path: "index.html", Size: 1, SHA256: validHash[:62]},
		}},
		"sha256 uppercase": {Index: "index.html", Files: []types.StaticCacheFile{
			{Path: "index.html", Size: 1, SHA256: strings.ToUpper(validHash)},
		}},
		"missing index entry": {Index: "missing.html", Files: []types.StaticCacheFile{
			{Path: "index.html", Size: 1, SHA256: validHash},
		}},
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := manifestDigest(manifest, 1<<20, 1<<20); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestManifestDigestBindsFileContents(t *testing.T) {
	manifest := types.StaticCacheManifest{Index: "a.html", Files: []types.StaticCacheFile{
		{Path: "a.html", Size: 1, SHA256: strings.Repeat("a", 64)},
		{Path: "b.html", Size: 2, SHA256: strings.Repeat("b", 64)},
	}}
	digest, total, err := manifestDigest(manifest, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if total != manifest.Files[0].Size+manifest.Files[1].Size {
		t.Fatalf("manifest byte total = %d, want sum of file sizes", total)
	}
	manifest.Files[1].SHA256 = strings.Repeat("c", 64)
	changed, _, err := manifestDigest(manifest, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if changed == digest {
		t.Fatal("manifest digest did not change when file content digest changed")
	}
}
