package policy

import (
	"cmp"
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

func ensureLoadStoredReputationComments(path string, state *persistedReputation) (bool, error) {
	commentsMissing := state.Comments == nil
	if state.Comments == nil {
		comments, err := loadLegacyComments(filepath.Dir(path))
		if err != nil {
			return false, err
		}
		state.Comments = comments
	}
	if state.Comments.Threads == nil {
		state.Comments.Threads = make(map[string][]storedComment)
	}
	if state.Comments.Votes == nil {
		state.Comments.Votes = make(map[string]map[string]string)
	}
	if state.Comments.Authors == nil {
		state.Comments.Authors = make(map[string]string)
	}
	return commentsMissing, nil
}

func loadStoredReputation(path string) (persistedReputation, bool, error) {
	var state persistedReputation
	if _, err := utils.ReadJSONFileIfExists(path, &state); err != nil {
		return persistedReputation{}, false, fmt.Errorf("load reputation state: %w", err)
	}
	if state.Identities == nil {
		state.Identities = make(map[string]map[string]string)
	}
	if err := validateIdentities(state.Identities); err != nil {
		return persistedReputation{}, false, err
	}
	commentsMissing, err := ensureLoadStoredReputationComments(path, &state)
	if err != nil {
		return persistedReputation{}, false, err
	}
	return state, commentsMissing, nil
}

func NewReputationStore(path string) (*ReputationStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errReputationStoreRequiresStatePath
	}
	state, commentsMissing, err := loadStoredReputation(path)
	if err != nil {
		return nil, err
	}
	store := &ReputationStore{
		path:               path,
		limiter:            NewSourceLimiter(10, 20, 120, 40),
		commentPostLimiter: NewSourceLimiter(3, 3, 30, 10),
		commentVoteLimiter: NewSourceLimiter(10, 20, 120, 40),
		state:              state,
	}
	if err := store.validateComments(); err != nil {
		return nil, err
	}
	needsWrite := commentsMissing || len(store.state.VoterSecret) == 0
	if err := store.ensureVoterSecret(); err != nil {
		return nil, err
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

func voterCapacityExceededLocked(previous map[string]string, hash, vote string) bool {
	if _, exists := previous[hash]; !exists && vote != VoteClear {
		if len(previous) >= reputationMaxVoters {
			return true
		}
	}
	return false
}

func (s *ReputationStore) admitAppVoteCapacityLocked(source netip.Addr, minted string, ledger map[string]map[string]string, previous map[string]string) error {
	if previous == nil && len(ledger) >= reputationMaxIdentities {
		return ErrReputationCapacity
	}
	if minted != "" {
		if retry, _ := s.limiter.Allow(source, 10); retry > 0 {
			return ErrReputationCapacity
		}
	}
	return nil
}

func countCommentVotesLocked(ledger map[string]map[string]string) int {
	total := 0
	for _, votes := range ledger {
		total += len(votes)
	}
	return total
}

func applyVoteToLedgerLocked(ledger map[string]map[string]string, key, hash, vote string) (map[string]map[string]string, map[string]string) {
	nextLedger := maps.Clone(ledger)
	votes := maps.Clone(ledger[key])
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
	return nextLedger, votes
}

func (s *ReputationStore) storeVoteLedgerLocked(commentID, key string, nextLedger map[string]map[string]string) error {
	nextState := s.state
	if commentID == "" {
		nextState.Identities = nextLedger
	} else {
		comments := *s.state.Comments
		comments.Votes = nextLedger
		nextState.Comments = &comments
	}
	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return fmt.Errorf("persist vote: %w", err)
	}
	s.state = nextState
	return nil
}

func (s *ReputationStore) selectVoteLedgerLocked(identity, commentID string) (map[string]map[string]string, string, error) {
	if identity == "" {
		return nil, "", ErrReputationUnknownHostname
	}
	if commentID == "" {
		return s.state.Identities, identity, nil
	}
	if !slices.ContainsFunc(s.state.Comments.Threads[identity], func(c storedComment) bool { return c.ID == commentID }) {
		return nil, "", ErrCommentNotFound
	}
	return s.state.Comments.Votes, commentID, nil
}
func isVoteRepeatLocked(previous map[string]string, hash, vote string) bool {
	return previous[hash] == vote || (vote == VoteClear && previous[hash] == "")
}

func checkVoteCapacityLocked(previous map[string]string, hash, vote, commentID string) error {
	if !voterCapacityExceededLocked(previous, hash, vote) {
		return nil
	}
	if commentID != "" {
		return ErrCommentCapacity
	}
	return ErrReputationCapacity
}

func (s *ReputationStore) persistVoteBallotLocked(commentID, key, hash, vote string) (VoteSummary, error) {
	ledger := s.state.Identities
	if commentID != "" {
		ledger = s.state.Comments.Votes
	}
	nextLedger, votes := applyVoteToLedgerLocked(ledger, key, hash, vote)
	if err := s.storeVoteLedgerLocked(commentID, key, nextLedger); err != nil {
		return VoteSummary{}, err
	}
	return summarizeVotes(votes, hash), nil
}

func isVoteChoiceValid(vote string) bool {
	return vote == VoteUp || vote == VoteDown || vote == VoteClear
}

func (s *ReputationStore) prepareVoteBallotLocked(cookieID, identity, commentID string, source netip.Addr) (map[string]map[string]string, string, map[string]string, string, string, error) {
	ledger, key, err := s.selectVoteLedgerLocked(identity, commentID)
	if err != nil {
		return nil, "", nil, "", "", err
	}
	hash, minted, err := s.resolveVoterLocked(cookieID, source)
	if err != nil {
		return nil, "", nil, "", "", err
	}
	return ledger, key, ledger[key], hash, minted, nil
}

func (s *ReputationStore) admitVoteNewVoterLocked(source netip.Addr, minted, commentID, key string) error {
	if commentID != "" {
		if countCommentVotesLocked(s.state.Comments.Votes) >= commentsMaxVotes {
			return ErrCommentCapacity
		}
		return nil
	}
	return s.admitAppVoteCapacityLocked(source, minted, s.state.Identities, s.state.Identities[key])
}

func (s *ReputationStore) Vote(identity, commentID, vote, cookieID string, source netip.Addr) (VoteSummary, string, error) {
	vote = strings.TrimSpace(vote)
	if !isVoteChoiceValid(vote) {
		return VoteSummary{}, "", ErrVoteChoice
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, key, previous, hash, minted, err := s.prepareVoteBallotLocked(cookieID, identity, commentID, source)
	if err != nil {
		return VoteSummary{}, "", err
	}
	if isVoteRepeatLocked(previous, hash, vote) {
		return summarizeVotes(previous, hash), minted, nil
	}
	if err := checkVoteCapacityLocked(previous, hash, vote, commentID); err != nil {
		return VoteSummary{}, "", err
	}
	if _, exists := previous[hash]; !exists && vote != VoteClear {
		if err := s.admitVoteNewVoterLocked(source, minted, commentID, key); err != nil {
			return VoteSummary{}, "", err
		}
	}
	summary, err := s.persistVoteBallotLocked(commentID, key, hash, vote)
	if err != nil {
		return VoteSummary{}, "", err
	}
	return summary, minted, nil
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
