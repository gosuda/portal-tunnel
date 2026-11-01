package policy

// Service reputation: relay-local, stable-identity-keyed up/down votes.
//
// The relay's lease registry owns service lifecycle. This file owns only the
// bounded vote ledger, the voter cookie secret, and the per-source vote
// budget; the vote wire path and HTTP handling stay with the relay API.

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var errReputationStoreRequiresStatePath = errors.New("reputation store requires a state path")

// Vote values are the relay-local wire contract mirrored by the frontend.
const (
	VoteUp   = "up"
	VoteDown = "down"
)

const (
	reputationVoterIDBytes = 32

	// Whole-file JSON is rewritten on each changed vote so these caps keep
	// the work per public POST small; identities persist for the life of
	// the state file, so past the identity cap new identities are rejected.
	reputationMaxVoters     = 1024
	reputationMaxIdentities = 4096
)

// persistedReputation is the reputation.json schema. All collections are
// bounded by the reputationMax* constants.
type persistedReputation struct {
	VoterSecret []byte                       `json:"voter_secret"`
	Identities  map[string]map[string]string `json:"identities,omitempty"`
}

// ReputationSummary is one directory row for a live hostname.
type ReputationSummary struct {
	Hostname   string `json:"hostname"`
	Up         int    `json:"up"`
	Down       int    `json:"down"`
	Total      int    `json:"total"`
	ViewerVote string `json:"viewer_vote"` // "" | "up" | "down"
}

var (
	ErrReputationUnknownHostname = errors.New("hostname is not in the public directory")
	ErrReputationCapacity        = errors.New("reputation capacity exhausted")
)

// ReputationStore owns the bounded vote ledger, the voter cookie secret, and
// the per-source vote budget.
type ReputationStore struct {
	path    string
	limiter *SourceLimiter

	mu     sync.Mutex
	state  persistedReputation
	secret []byte
}

func NewReputationStore(path string) (*ReputationStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errReputationStoreRequiresStatePath
	}
	store := &ReputationStore{path: path}
	_, err := utils.ReadJSONFileIfExists(path, &store.state)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if store.state.Identities == nil {
		store.state.Identities = make(map[string]map[string]string)
	}
	if len(store.state.VoterSecret) == 0 {
		store.state.VoterSecret = make([]byte, reputationVoterIDBytes)
		if _, err := rand.Read(store.state.VoterSecret); err != nil {
			return nil, fmt.Errorf("generate reputation voter secret: %w", err)
		}
		if err := utils.WriteJSONFile(store.path, store.state, 0o600); err != nil {
			return nil, fmt.Errorf("persist reputation voter secret: %w", err)
		}
	}
	store.secret = store.state.VoterSecret
	store.limiter = NewSourceLimiter(10, 20, 120, 40)
	return store, nil
}

// AllowVote spends the per-source vote budget before the request body is
// decoded and returns the retry guidance when the source is exhausted.
func (s *ReputationStore) AllowVote(source netip.Addr) time.Duration {
	retry, _ := s.limiter.Allow(source, 1)
	return retry
}

// CastVote resolves a signed cookie or a stable source-bound voter identity,
// applies the vote, and persists atomically under one lock. The returned
// cookie is reissued for requests without a valid cookie, but never creates
// another voter for the same source. Identity comes from public leases.
func (s *ReputationStore) CastVote(hostname, identity, vote, cookieID string, source netip.Addr) (ReputationSummary, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity == "" {
		return ReputationSummary{}, "", ErrReputationUnknownHostname
	}
	hash, minted, err := s.resolveVoterLocked(cookieID, source)
	if err != nil {
		return ReputationSummary{}, "", err
	}

	previous := s.state.Identities[identity]
	if previous != nil && previous[hash] == vote {
		return s.summarize(hostname, previous, hash), minted, nil
	}
	if previous == nil && len(s.state.Identities) >= reputationMaxIdentities {
		return ReputationSummary{}, "", ErrReputationCapacity
	}
	if _, exists := previous[hash]; !exists {
		if len(previous) >= reputationMaxVoters {
			return ReputationSummary{}, "", ErrReputationCapacity
		}
		// Cookie-free creation still spends the source and shared mint budget.
		// Reissuing an existing voter's cookie must not pay this charge again.
		if minted != "" {
			if retry, _ := s.limiter.Allow(source, 10); retry > 0 {
				return ReputationSummary{}, "", ErrReputationCapacity
			}
		}
	}
	nextIdentities := maps.Clone(s.state.Identities)
	votes := maps.Clone(previous)
	if votes == nil {
		votes = make(map[string]string)
	}
	votes[hash] = vote
	nextIdentities[identity] = votes
	nextState := s.state
	nextState.Identities = nextIdentities

	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return ReputationSummary{}, "", fmt.Errorf("persist reputation: %w", err)
	}
	s.state = nextState
	return s.summarize(hostname, votes, hash), minted, nil
}

func (s *ReputationStore) Summaries(viewerHash string, leases []types.PolicyLease) []ReputationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]ReputationSummary, 0, len(leases))
	for _, lease := range leases {
		hostname := cmp.Or(lease.CanonicalHostname, lease.Hostname)
		rows = append(rows, s.summarize(hostname, s.state.Identities[lease.IdentityKey], viewerHash))
	}
	return rows
}

// ViewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous; source-derived identities
// are issued only on votes.
func (s *ReputationStore) ViewerHashFor(cookieID string) string {
	if cookieID == "" {
		return ""
	}
	hash, ok := s.verifyVoter(cookieID)
	if !ok {
		return ""
	}
	return hash
}

// resolveVoterLocked returns the digest of a verified cookie or derives one
// deterministically from the trusted client source. A caller that drops every
// Set-Cookie header cannot create unlimited distinct voter identities.
// Without accounts, clients behind the same public IP share this identity.
func (s *ReputationStore) resolveVoterLocked(cookieID string, source netip.Addr) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoter(cookieID); ok {
			return verified, "", nil
		}
	}
	if !source.IsValid() {
		return "", "", ErrReputationCapacity
	}
	sourceMAC := hmac.New(sha256.New, s.secret)
	_, _ = sourceMAC.Write([]byte("reputation-source-v1\x00"))
	_, _ = sourceMAC.Write(source.Unmap().AsSlice())
	id := sourceMAC.Sum(nil)
	digest := s.voterMAC(id)
	hash = hex.EncodeToString(digest)
	return hash, base64.RawURLEncoding.EncodeToString(append(id, digest...)), nil
}

func (s *ReputationStore) verifyVoter(cookieID string) (string, bool) {
	value, err := base64.RawURLEncoding.DecodeString(cookieID)
	if err != nil || len(value) != reputationVoterIDBytes+sha256.Size {
		return "", false
	}
	expected := s.voterMAC(value[:reputationVoterIDBytes])
	if subtle.ConstantTimeCompare(expected, value[reputationVoterIDBytes:]) != 1 {
		return "", false
	}
	return hex.EncodeToString(expected), true
}

func (s *ReputationStore) voterMAC(id []byte) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(id)
	return mac.Sum(nil)
}

// summarize projects one hostname's row, zero-count when rec is nil so a
// newly live hostname without a record still renders with vote controls.
func (s *ReputationStore) summarize(hostname string, votes map[string]string, viewerHash string) ReputationSummary {
	if votes == nil {
		return ReputationSummary{Hostname: hostname}
	}
	up, down := 0, 0
	for _, vote := range votes {
		switch vote {
		case VoteUp:
			up++
		case VoteDown:
			down++
		}
	}
	return ReputationSummary{
		Hostname:   hostname,
		Up:         up,
		Down:       down,
		Total:      up + down,
		ViewerVote: votes[viewerHash],
	}
}
