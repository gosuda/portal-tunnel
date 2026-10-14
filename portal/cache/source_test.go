package cache

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

// TestSubscriptionLimitsSurviveReplacedListenerClose pins subscription-entry
// ownership: a replaced listener's late Close must not remove the live
// replacement's limits entry, and the surviving subscription keeps receiving
// published generations after the source changes.
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

	runCtx, cancelRun := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		source.Run(runCtx)
		close(done)
	}()
	t.Cleanup(func() {
		cancelRun()
		<-done
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !replacement.Next(ctx) {
		t.Fatal("replacement listener did not receive a published generation")
	}
	previous := replacement.snapshot.manifest.Files[0].SHA256

	// A source change must still publish to the surviving subscription.
	if err := os.WriteFile(indexPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.snapshot = nil
	source.mu.Unlock()
	select {
	case source.wake <- struct{}{}:
	default:
	}
	if !replacement.Next(ctx) {
		t.Fatal("surviving subscription did not receive the republished generation")
	}
	if current := replacement.snapshot.manifest.Files[0].SHA256; current == previous {
		t.Fatal("republished generation did not pick up the source change")
	}
}
