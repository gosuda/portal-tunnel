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

// ObservedServiceReputation is a relay-reported tally, not unique voters or proof.
type ObservedServiceReputation struct {
	Up   uint32 `json:"up"`
	Down uint32 `json:"down"`
}

type ServiceLocation struct {
	RelayURL      string                     `json:"relay_url"`
	URL           string                     `json:"url,omitempty"`
	CanonicalURL  string                     `json:"canonical_url,omitempty"`
	AliasURL      string                     `json:"alias_url,omitempty"`
	TCPAddr       string                     `json:"tcp_addr,omitempty"`
	UDPAddr       string                     `json:"udp_addr,omitempty"`
	CurrentRelay  bool                       `json:"current_relay"`
	ReportedReady bool                       `json:"reported_ready"`
	ObservedAt    time.Time                  `json:"observed_at"`
	ExpiresAt     time.Time                  `json:"expires_at"`
	Verification  string                     `json:"verification"` // Always "relay-reported" in v1.
	Reputation    *ObservedServiceReputation `json:"reputation,omitempty"`
}

// ObservedServiceComment is read-only public text from an independent relay.
// The timestamp and ID are claims of that source, not global identifiers.
type ObservedServiceComment struct {
	RelayURL  string    `json:"relay_url"`
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
	Deleted   bool      `json:"deleted,omitempty"`
}

type ServiceCommentsResponse struct {
	Comments      []ObservedServiceComment `json:"comments"`
	RelaysChecked int                      `json:"relays_checked"`
	RelaysSkipped int                      `json:"relays_skipped"`
	Partial       bool                     `json:"partial"`
}
