package types

import "time"

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
