package types

import (
	"errors"
	"time"
)

// ReputationConfig holds the relay-adjustable reputation verdict settings.
type ReputationConfig struct {
	// MinTotal and MinDown floor the vote counts, MinDownRatioPercent the
	// down-vote share, before a hostname is flagged as a service warning.
	MinTotal            int
	MinDown             int
	MinDownRatioPercent int
	// Probation is how long a hostname counts as new and how long an owner-key
	// change stays flagged as identity_changed_recently.
	Probation time.Duration
	// Retention is how long a hostname's reputation survives without appearing
	// in the public lease set.
	Retention time.Duration
	// VoteSourcePerMinute and VoteSourceBurst bound per-source vote admission.
	VoteSourcePerMinute int
	VoteSourceBurst     int
	// MaxVotersPerSource caps how many distinct voter IDs a single source may
	// mint without a cookie. The default (2) is below MinDown (3) so that
	// cookieless minting alone cannot trigger a service warning.
	// In-memory only; resets on relay restart.
	MaxVotersPerSource int
	// MaxVotersPerHostname caps distinct voters per hostname. New voters are
	// rejected with 429 when this limit is reached; existing voters may still
	// change their vote.
	MaxVotersPerHostname int
	// MaxHostnames is the relay-wide cap on distinct hostnames with any votes.
	// When exceeded, the hostname whose LastSeenAt is oldest is evicted to
	// make room for a new one.
	MaxHostnames int
}

func DefaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		MinTotal:             5,
		MinDown:              3,
		MinDownRatioPercent:  70,
		Probation:            7 * 24 * time.Hour,
		Retention:            30 * 24 * time.Hour,
		VoteSourcePerMinute:  6,
		VoteSourceBurst:      12,
		MaxVotersPerSource:   2,
		MaxVotersPerHostname: 512,
		MaxHostnames:         1024,
	}
}

func (c ReputationConfig) Validate() error {
	if c.MinTotal < 0 || c.MinDown < 0 {
		return errors.New("reputation vote minimums must be non-negative")
	}
	if c.MinDownRatioPercent < 0 || c.MinDownRatioPercent > 100 {
		return errors.New("reputation down ratio percent must be within 0-100")
	}
	if c.Probation <= 0 || c.Retention <= 0 {
		return errors.New("reputation probation and retention must be positive")
	}
	if c.VoteSourcePerMinute <= 0 || c.VoteSourceBurst <= 0 {
		return errors.New("reputation vote limits must be positive")
	}
	if c.MaxVotersPerSource <= 0 {
		return errors.New("reputation max voters per source must be positive")
	}
	if c.MaxVotersPerHostname <= 0 {
		return errors.New("reputation max voters per hostname must be positive")
	}
	if c.MaxHostnames <= 0 {
		return errors.New("reputation max hostnames must be positive")
	}
	return nil
}
