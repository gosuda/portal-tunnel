package types

import (
	"errors"
	"slices"
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
	// Admission beyond the cap evicts the oldest voteless record; voted
	// records are never evicted, so a full set of voted hostnames rejects new
	// ones with 429.
	MaxHostnames int
	// MaxMintSources caps how many distinct source IPs may hold cookieless
	// minted voter IDs. New sources beyond the cap are rejected with 429
	// (fail-closed); existing sources keep their own budgets. In-memory only;
	// resets on relay restart.
	MaxMintSources int
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
		MaxMintSources:       4096,
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
	if c.MaxMintSources <= 0 {
		return errors.New("reputation max mint sources must be positive")
	}
	return nil
}

// ReputationMeta is the top-level JSON structure persisted to reputation.json.
// It carries the voter-secret derivation key and the hostname reputation map,
// so that secret rotation preserves voter continuity across relay restarts.
type ReputationMeta struct {
	// VoterSecret is the relay-scoped secret used to derive voter HMACs.
	// It is generated once on first startup and persisted in the state file.
	// Generating it from the relay identity allows restarts without explicit
	// migration while remaining distinct per relay.
	VoterSecret []byte                       `json:"voter_secret,omitempty"`
	Hostnames   map[string]*ReputationRecord `json:"hostnames"`
}

// Copy returns a deep copy of the reputation metadata, including all hostname
// records and their voter slices. Used for rollback on persist failure.
func (m ReputationMeta) Copy() ReputationMeta {
	hostnames := make(map[string]*ReputationRecord, len(m.Hostnames))
	for k, v := range m.Hostnames {
		if v == nil {
			continue
		}
		hostnames[k] = &ReputationRecord{
			UpVoters:        slices.Clone(v.UpVoters),
			DownVoters:      slices.Clone(v.DownVoters),
			OwnerKey:        v.OwnerKey,
			OwnerKeyHistory: slices.Clone(v.OwnerKeyHistory),
			FirstSeenAt:     v.FirstSeenAt,
			LastSeenAt:      v.LastSeenAt,
		}
	}
	return ReputationMeta{
		VoterSecret: slices.Clone(m.VoterSecret),
		Hostnames:   hostnames,
	}
}

// ReputationRecord is the per-hostname reputation state persisted to
// reputation.json. Voter identities are stored only as HMACs.
type ReputationRecord struct {
	UpVoters   []string `json:"up_voters,omitempty"`
	DownVoters []string `json:"down_voters,omitempty"`
	// OwnerKey is the identity key observed at the latest registration.
	OwnerKey string `json:"owner_key,omitempty"`
	// OwnerKeyHistory lists previous owner keys, most recent first, with the
	// moment the key was replaced. A signature-based rotation proof that
	// distinguishes operator rotation from takeover is a follow-up; for now
	// any owner-key difference flags identity_changed_recently.
	OwnerKeyHistory []OwnerKeySpan `json:"owner_key_history,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// OwnerKeySpan records one replaced owner key and when it was replaced.
type OwnerKeySpan struct {
	Key       string    `json:"key"`
	ChangedAt time.Time `json:"changed_at"`
}
