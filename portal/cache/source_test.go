package cache

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestSubscriptionLimitsSurviveReplacedListenerClose pins subscription-entry
// ownership: a replaced listener's late Close must not remove the live
// replacement's limits entry.
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
	relayURL, err := url.Parse("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	replaced := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	replacement := source.Subscribe(*relayURL, types.StaticCacheLimits{MaxExposureBytes: 1024, MaxObjectSize: 512})
	replaced.Close()

	// The late Close of the replaced generation must leave exactly the live
	// replacement registered, keyed by its own subscription instance.
	source.mu.Lock()
	owned := len(source.limits) == 1 && source.limits[replacement] == replacement.limits
	source.mu.Unlock()
	if !owned {
		t.Fatalf("replaced listener's Close disturbed the live registration: %d entries remain", len(source.limits))
	}
}
