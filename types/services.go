package types

import "time"

// ServiceDiscoveryResponse contains bounded observations, never an exhaustive
// inventory or independently authenticated proof of service ownership.
type ServiceDiscoveryResponse struct {
	Services      []DiscoveredService `json:"services"`
	Partial       bool                `json:"partial"`
	RelaysChecked int                 `json:"relays_checked"`
	RelaysSkipped int                 `json:"relays_skipped"`
}

type DiscoveredService struct {
	Name      string            `json:"name"`
	Address   string            `json:"address"`
	Metadata  LeaseMetadata     `json:"metadata"`
	Locations []ServiceLocation `json:"locations"`
}

type ServiceLocation struct {
	RelayURL      string    `json:"relay_url"`
	URL           string    `json:"url,omitempty"`
	CanonicalURL  string    `json:"canonical_url,omitempty"`
	AliasURL      string    `json:"alias_url,omitempty"`
	CurrentRelay  bool      `json:"current_relay"`
	ReportedReady bool      `json:"reported_ready"`
	ObservedAt    time.Time `json:"observed_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Verification  string    `json:"verification"` // Always "relay-reported" in v1.
}
