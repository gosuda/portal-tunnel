package cache

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestSubscriptionLimitsSurviveReplacedListenerClose(t *testing.T) {
	root := t.TempDir()
	indexPath := filepath.Join(root, "index.html")
	if err := os.WriteFile(indexPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	replaced := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	replacement := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	replaced.Close()
	t.Cleanup(replacement.Close)

	source.mu.Lock()
	owned := len(source.limits) == 1 && source.limits[replacement] == replacement.limits
	source.mu.Unlock()
	if !owned {
		t.Fatalf("replaced listener's Close disturbed the live registration: %d entries remain", len(source.limits))
	}
}

func TestSourcePinsRootAcrossScanAndUpload(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "site")
	replacement := filepath.Join(parent, "replacement")
	for path, content := range map[string]string{
		root:        "original content",
		replacement: "replacement secret",
	} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "index.html"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(replacement, "secret.txt"), []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	source, err := NewSource(SourceConfig{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	if err := os.Rename(root, filepath.Join(parent, "opened-site")); err != nil {
		t.Skipf("cannot rename opened cache root: %v", err)
	}
	if err := os.Rename(replacement, root); err != nil {
		t.Fatal(err)
	}

	limits := types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}
	snapshot := source.scan(context.Background(), limits)
	if snapshot.err != nil {
		t.Fatal(snapshot.err)
	}
	if len(snapshot.manifest.Files) != 1 || snapshot.manifest.Files[0].Path != "index.html" {
		t.Fatalf("manifest files = %#v, want only the opened root index", snapshot.manifest.Files)
	}
	var upload bytes.Buffer
	parts := multipart.NewWriter(&upload)
	if err := writeSnapshotUpload(context.Background(), parts, snapshot.root, snapshot.manifest); err != nil {
		t.Fatal(err)
	}
	if body := upload.String(); !strings.Contains(body, "original content") || strings.Contains(body, "replacement secret") || strings.Contains(body, "host secret") {
		t.Fatalf("upload used replacement root: %q", body)
	}
}

func TestSourceCloseWaitsForSubscribers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("site"), 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := NewSource(SourceConfig{Path: root})
		if err != nil {
			t.Fatal(err)
		}
		relayURL, err := url.Parse("https://relay.example")
		if err != nil {
			t.Fatal(err)
		}
		syncer := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
		closed := make(chan error, 1)
		go func() { closed <- source.Close() }()
		synctest.Wait()

		select {
		case err := <-closed:
			t.Fatalf("Close() = %v returned while a subscriber could still upload", err)
		default:
		}
		if _, err := source.root.Stat("index.html"); err != nil {
			t.Fatalf("root closed under a live subscriber: %v", err)
		}
		if late := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512}); late != nil {
			t.Fatal("Subscribe() succeeded on a closing source")
		}

		syncer.Close()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if _, err := source.root.Stat("index.html"); err == nil {
			t.Fatal("root still open after the last subscriber closed")
		}
	})
}
