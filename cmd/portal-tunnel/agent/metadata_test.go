package agent

import "testing"

// A thumbnail found by --thumbnail-from-target is not in cfg, so anything that
// rebuilds metadata from cfg alone erases it. UpdateSettings and Snapshot both
// do exactly that, which meant the discovered image appeared once at startup
// and vanished at the first metadata update.
func TestTunnelMetadataKeepsTheDiscoveredThumbnail(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/card.png"}

	got := tunnel.metadata(TunnelConfig{Name: "app", ThumbnailFromTarget: true}).Thumbnail
	if got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the discovered value to survive", got)
	}
}

// An explicit value wins here for the same reason it wins at startup: the
// operator answered the question already.
func TestTunnelMetadataPrefersTheConfiguredThumbnail(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/discovered.png"}
	cfg := TunnelConfig{Name: "app", Thumbnail: "https://example.com/explicit.png", ThumbnailFromTarget: true}

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

// Turning the opt-in off in a later update retires the discovered value with
// it: the flag no longer applies, so neither does what it once found.
func TestTunnelMetadataDropsDiscoveredThumbnailWhenOptInRemoved(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/card.png"}

	if got := tunnel.metadata(TunnelConfig{Name: "app"}).Thumbnail; got != "" {
		t.Fatalf("thumbnail = %q, want empty once thumbnail_from_target is off", got)
	}
}

// An explicit thumbnail must never sit in the discovered slot: a later update
// that clears thumbnail would resurrect it from there. The store is gated on
// discovery having actually applied.
func TestRecordDiscoveredThumbnailIgnoresExplicitValue(t *testing.T) {
	tunnel := &managedTunnel{}
	tunnel.recordDiscoveredThumbnail(
		TunnelConfig{Name: "app", Thumbnail: "https://example.com/explicit.png", ThumbnailFromTarget: true},
		"https://example.com/explicit.png")

	if got := tunnel.metadata(TunnelConfig{Name: "app", ThumbnailFromTarget: true}).Thumbnail; got != "" {
		t.Fatalf("thumbnail = %q, want empty — the cleared explicit value must not come back", got)
	}
}

func TestRecordDiscoveredThumbnailClearsWithoutOptIn(t *testing.T) {
	tunnel := &managedTunnel{discoveredThumbnail: "https://cdn.example.com/old.png"}
	tunnel.recordDiscoveredThumbnail(TunnelConfig{Name: "app"}, "")

	if tunnel.discoveredThumbnail != "" {
		t.Fatalf("discoveredThumbnail = %q, want cleared", tunnel.discoveredThumbnail)
	}
}

func TestRecordDiscoveredThumbnailKeepsDiscoveryResult(t *testing.T) {
	tunnel := &managedTunnel{}
	tunnel.recordDiscoveredThumbnail(
		TunnelConfig{Name: "app", ThumbnailFromTarget: true},
		"https://cdn.example.com/card.png")

	if got := tunnel.metadata(TunnelConfig{Name: "app", ThumbnailFromTarget: true}).Thumbnail; got != "https://cdn.example.com/card.png" {
		t.Fatalf("thumbnail = %q, want the discovered value", got)
	}
}
