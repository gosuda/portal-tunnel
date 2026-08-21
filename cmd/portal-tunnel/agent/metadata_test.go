package agent

import "testing"

// A thumbnail found by --thumbnail-from-target is not in cfg, so anything that
// rebuilds metadata from cfg alone erases it. UpdateSettings and Snapshot both
// do exactly that, which meant the discovered image appeared once at startup
// and vanished at the first metadata update.
func TestTunnelMetadataKeepsTheDiscoveredThumbnail(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/card.png"}

	got := tunnel.metadata(TunnelConfig{Name: "app"}).Thumbnail
	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the discovered value to survive", got)
	}
}

// An explicit value wins here for the same reason it wins at startup: the
// operator answered the question already.
func TestTunnelMetadataPrefersTheConfiguredThumbnail(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/discovered.png"}
	cfg := TunnelConfig{Name: "app", Thumbnail: "https://example.com/explicit.png"}

	if got := tunnel.metadata(cfg).Thumbnail; got != "https://example.com/explicit.png" {
		t.Fatalf("thumbnail = %q, want the configured value", got)
	}
}

func TestTunnelMetadataLeavesThumbnailEmptyWithoutDiscovery(t *testing.T) {
	tunnel := &managedTunnel{}

	if got := tunnel.metadata(TunnelConfig{Name: "app"}).Thumbnail; got != "" {
		t.Fatalf("thumbnail = %q, want empty", got)
	}
}
