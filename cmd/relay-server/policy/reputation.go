package policy

// Service reputation: relay-local, stable-identity-keyed up/down votes.
//
// The relay's lease registry owns service lifecycle. This file owns only the
// bounded vote ledger, the voter cookie secret, and the per-source vote
// budget; the vote wire path and HTTP handling stay with the relay API.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
	reputationMaxVoters     = 64
	reputationMaxIdentities = 128
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
		return nil, errors.New("reputation store requires a state path")
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
func (s *ReputationStore) AllowVote(source string) time.Duration {
	retry, _ := s.limiter.Allow(source, 1)
	return retry
}

// CastVote resolves the voter (minting a cookieless identity when needed),
// applies the vote, and persists atomically under one lock. The returned
// mint value is a fresh cookie value, set only when a new voter was minted.
// The identity comes from the relay's current public leases.
func (s *ReputationStore) CastVote(hostname, identity, vote, cookieID, source string) (ReputationSummary, string, error) {
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
	nextIdentities := maps.Clone(s.state.Identities)
	votes := maps.Clone(previous)
	if votes == nil {
		votes = make(map[string]string)
	}
	if _, exists := votes[hash]; !exists && len(votes) >= reputationMaxVoters {
		return ReputationSummary{}, "", ErrReputationCapacity
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
		rows = append(rows, s.summarize(lease.Hostname, s.state.Identities[lease.IdentityKey], viewerHash))
	}
	return rows
}

// ViewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous; the cookieless mint path
// exists only on votes.
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

// resolveVoterLocked returns the digest for a verified cookie or mints a new
// cookieless identity. Signed cookies need no persisted global voter registry.
func (s *ReputationStore) resolveVoterLocked(cookieID, source string) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoter(cookieID); ok {
			return verified, "", nil
		}
	}
	if retry, _ := s.limiter.Allow(source, 10); retry > 0 {
		return "", "", ErrReputationCapacity
	}
	id := make([]byte, reputationVoterIDBytes)
	if _, err := rand.Read(id); err != nil {
		return "", "", fmt.Errorf("generate voter id: %w", err)
	}
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
