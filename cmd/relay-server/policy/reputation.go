package policy

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errReputationStoreRequiresStatePath = errors.New("reputation store requires a state path")
	errReputationStoredInvalid          = errors.New("invalid stored app votes")
)

// Vote values are the relay-local wire contract mirrored by the frontend.
const (
	VoteUp    = "up"
	VoteDown  = "down"
	VoteClear = "clear"
)

const (
	reputationVoterIDBytes = 32

	reputationMaxVoters     = 1024
	reputationMaxIdentities = 4096
)

type persistedReputation struct {
	VoterSecret []byte                       `json:"voter_secret"`
	Identities  map[string]map[string]string `json:"identities,omitempty"`
	Comments    *persistedComments           `json:"comments"`
}

// VoteSummary is the aggregate of one app's or comment's votes.
type VoteSummary struct {
	Up         int    `json:"up"`
	Down       int    `json:"down"`
	Total      int    `json:"total"`
	ViewerVote string `json:"viewer_vote"`
}

// ReputationSummary is one directory row for a live hostname.
type ReputationSummary struct {
	Hostname string `json:"hostname"`
	Comments int    `json:"comments"`
	VoteSummary
}

var (
	ErrReputationUnknownHostname = errors.New("hostname is not in the public directory")
	ErrReputationCapacity        = errors.New("reputation capacity exhausted")
	ErrVoteChoice                = errors.New("vote must be 'up', 'down', or 'clear'")
)

// ReputationStore owns app votes, comments and their votes, voter identities,
// and admission budgets under one lock and in one state file.
type ReputationStore struct {
	path               string
	limiter            *SourceLimiter
	commentPostLimiter *SourceLimiter
	commentVoteLimiter *SourceLimiter

	mu     sync.Mutex
	state  persistedReputation
	secret []byte
}

func NewReputationStore(path string) (*ReputationStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errReputationStoreRequiresStatePath
	}
	store := &ReputationStore{
		path:               path,
		limiter:            NewSourceLimiter(10, 20, 120, 40),
		commentPostLimiter: NewSourceLimiter(3, 3, 30, 10),
		commentVoteLimiter: NewSourceLimiter(10, 20, 120, 40),
	}
	_, err := utils.ReadJSONFileIfExists(path, &store.state)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if store.state.Identities == nil {
		store.state.Identities = make(map[string]map[string]string)
	}
	if err := validateIdentities(store.state.Identities); err != nil {
		return nil, err
	}
	needsWrite := store.state.Comments == nil || len(store.state.VoterSecret) == 0
	if store.state.Comments == nil {
		comments, err := loadLegacyComments(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		store.state.Comments = comments
	}
	if store.state.Comments.Threads == nil {
		store.state.Comments.Threads = make(map[string][]storedComment)
	}
	if store.state.Comments.Votes == nil {
		store.state.Comments.Votes = make(map[string]map[string]string)
	}
	if store.state.Comments.Authors == nil {
		store.state.Comments.Authors = make(map[string]string)
	}
	if err := store.validateComments(); err != nil {
		return nil, err
	}
	if len(store.state.VoterSecret) == 0 {
		store.state.VoterSecret = make([]byte, reputationVoterIDBytes)
		if _, err := rand.Read(store.state.VoterSecret); err != nil {
			return nil, fmt.Errorf("generate reputation voter secret: %w", err)
		}
	}
	if needsWrite {
		if err := utils.WriteJSONFile(store.path, store.state, 0o600); err != nil {
			return nil, fmt.Errorf("persist reputation state: %w", err)
		}
	}
	store.secret = store.state.VoterSecret
	return store, nil
}

func validateIdentities(identities map[string]map[string]string) error {
	if len(identities) > reputationMaxIdentities {
		return ErrReputationCapacity
	}
	for identity, votes := range identities {
		if strings.TrimSpace(identity) == "" || len(votes) == 0 {
			return errReputationStoredInvalid
		}
		if len(votes) > reputationMaxVoters {
			return ErrReputationCapacity
		}
		for voter, vote := range votes {
			if strings.TrimSpace(voter) == "" || (vote != VoteUp && vote != VoteDown) {
				return errReputationStoredInvalid
			}
		}
	}
	return nil
}

func loadLegacyComments(dir string) (*persistedComments, error) {
	comments := &persistedComments{}
	var raw json.RawMessage
	exists, err := utils.ReadJSONFileIfExists(filepath.Join(dir, "comments.json"), &raw)
	if err != nil {
		return nil, fmt.Errorf("load legacy comments: %w", err)
	}
	if !exists || len(raw) == 0 {
		return comments, nil
	}
	if err := json.Unmarshal(raw, comments); err == nil && comments.Threads != nil {
		return comments, nil
	}
	if err := json.Unmarshal(raw, &comments.Threads); err != nil {
		return nil, fmt.Errorf("load legacy comments: %w", err)
	}
	return comments, nil
}

// AllowVote spends the per-source vote budget before the request body is
// decoded and returns the retry guidance when the source is exhausted.
func (s *ReputationStore) AllowVote(source netip.Addr, comment bool) time.Duration {
	limiter := s.limiter
	if comment {
		limiter = s.commentVoteLimiter
	}
	retry, _ := limiter.Allow(source, 1)
	return retry
}

func (s *ReputationStore) Vote(identity, commentID, vote, cookieID string, source netip.Addr) (VoteSummary, string, error) {
	vote = strings.TrimSpace(vote)
	if vote != VoteUp && vote != VoteDown && vote != VoteClear {
		return VoteSummary{}, "", ErrVoteChoice
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity == "" {
		return VoteSummary{}, "", ErrReputationUnknownHostname
	}
	ledger, key := s.state.Identities, identity
	capacityErr := ErrReputationCapacity
	if commentID != "" {
		if !slices.ContainsFunc(s.state.Comments.Threads[identity], func(c storedComment) bool { return c.ID == commentID }) {
			return VoteSummary{}, "", ErrCommentNotFound
		}
		ledger, key = s.state.Comments.Votes, commentID
		capacityErr = ErrCommentCapacity
	}
	hash, minted, err := s.resolveVoterLocked(cookieID, source)
	if err != nil {
		return VoteSummary{}, "", err
	}
	previous := ledger[key]
	if previous[hash] == vote || (vote == VoteClear && previous[hash] == "") {
		return summarizeVotes(previous, hash), minted, nil
	}
	if _, exists := previous[hash]; !exists && vote != VoteClear {
		if len(previous) >= reputationMaxVoters {
			return VoteSummary{}, "", capacityErr
		}
		if commentID == "" {
			if previous == nil && len(ledger) >= reputationMaxIdentities {
				return VoteSummary{}, "", ErrReputationCapacity
			}
			if minted != "" {
				if retry, _ := s.limiter.Allow(source, 10); retry > 0 {
					return VoteSummary{}, "", ErrReputationCapacity
				}
			}
		} else {
			total := 0
			for _, votes := range ledger {
				total += len(votes)
			}
			if total >= commentsMaxVotes {
				return VoteSummary{}, "", ErrCommentCapacity
			}
		}
	}
	nextLedger := maps.Clone(ledger)
	votes := maps.Clone(previous)
	if votes == nil {
		votes = make(map[string]string)
	}
	if vote == VoteClear {
		delete(votes, hash)
	} else {
		votes[hash] = vote
	}
	if len(votes) == 0 {
		delete(nextLedger, key)
	} else {
		nextLedger[key] = votes
	}
	nextState := s.state
	if commentID == "" {
		nextState.Identities = nextLedger
	} else {
		comments := *s.state.Comments
		comments.Votes = nextLedger
		nextState.Comments = &comments
	}
	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return VoteSummary{}, "", fmt.Errorf("persist vote: %w", err)
	}
	s.state = nextState
	return summarizeVotes(votes, hash), minted, nil
}

func (s *ReputationStore) Summaries(viewerHash string, leases []types.PolicyLease) []ReputationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]ReputationSummary, 0, len(leases))
	for _, lease := range leases {
		hostname := cmp.Or(lease.CanonicalHostname, lease.Hostname)
		commentsCount := 0
		if s.state.Comments != nil {
			commentsCount = len(s.state.Comments.Threads[lease.IdentityKey])
		}
		rows = append(rows, ReputationSummary{
			Hostname:    hostname,
			Comments:    commentsCount,
			VoteSummary: summarizeVotes(s.state.Identities[lease.IdentityKey], viewerHash),
		})
	}
	return rows
}

// CommentsCount returns the number of comments posted for the given app identity.
func (s *ReputationStore) CommentsCount(identity string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Comments == nil {
		return 0
	}
	return len(s.state.Comments.Threads[identity])
}

// ViewerHashFor resolves a cookie to its voter digest for read paths.
// Unknown cookies read as anonymous.
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

func summarizeVotes(votes map[string]string, viewerHash string) VoteSummary {
	summary := VoteSummary{ViewerVote: votes[viewerHash]}
	for _, vote := range votes {
		switch vote {
		case VoteUp:
			summary.Up++
		case VoteDown:
			summary.Down++
		}
	}
	summary.Total = summary.Up + summary.Down
	return summary
}
