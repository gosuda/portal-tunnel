package policy

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	commentsMaxPerApp = 100
	commentsMaxTotal  = 1000
	commentsMaxVotes  = 10000
)

var (
	ErrCommentInvalid           = errors.New("comment must contain 1 to 2000 characters")
	ErrCommentCapacity          = errors.New("comment storage limit reached")
	ErrCommentNotFound          = errors.New("comment not found")
	ErrCommentStorePathRequired = errors.New("comments store requires a state path")
	ErrCommentThreadInvalid     = errors.New("invalid comment thread")
	ErrCommentStoredInvalid     = errors.New("invalid stored comment")
	ErrCommentVotesInvalid      = errors.New("invalid comment votes")
	ErrCommentVoteInvalid       = errors.New("invalid comment vote")
	ErrCommentAuthorInvalid     = errors.New("invalid comment author")
	ErrCommentVoteChoice        = errors.New("vote must be 'up', 'down', or 'clear'")
	ErrCommentVoterRequired     = errors.New("voter identification required")
)

type persistedComments struct {
	Threads map[string][]types.AppComment `json:"threads,omitempty"`
	Votes   map[string]map[string]string  `json:"votes,omitempty"`
	Authors map[string]string             `json:"authors,omitempty"`
}

// CommentsStore owns bounded, persistent threads keyed by lease identity, so
// changing a hostname never transfers comments to a different app owner.
type CommentsStore struct {
	path        string
	limiter     *SourceLimiter
	voteLimiter *SourceLimiter
	mu          sync.Mutex
	threads     map[string][]types.AppComment
	votes       map[string]map[string]string // commentID -> voterHash -> "up" | "down"
	authors     map[string]string            // commentID -> hash of the author's cookie
}

func NewCommentsStore(path string) (*CommentsStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrCommentStorePathRequired
	}
	s := &CommentsStore{
		path:        path,
		limiter:     NewSourceLimiter(3, 3, 30, 10),
		voteLimiter: NewSourceLimiter(10, 20, 120, 40),
		threads:     make(map[string][]types.AppComment),
		votes:       make(map[string]map[string]string),
		authors:     make(map[string]string),
	}
	var raw json.RawMessage
	exists, err := utils.ReadJSONFileIfExists(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("load comments: %w", err)
	}
	if exists && len(raw) > 0 {
		var persisted persistedComments
		if err := json.Unmarshal(raw, &persisted); err == nil && persisted.Threads != nil {
			s.threads = persisted.Threads
			if persisted.Votes != nil {
				s.votes = persisted.Votes
			}
			if persisted.Authors != nil {
				s.authors = persisted.Authors
			}
		} else {
			// Legacy fallback: top-level map[string][]types.AppComment
			var legacy map[string][]types.AppComment
			if err := json.Unmarshal(raw, &legacy); err != nil {
				return nil, fmt.Errorf("load comments: %w", err)
			}
			s.threads = legacy
		}
	}
	total := 0
	ids := make(map[string]bool)
	for identity, comments := range s.threads {
		if identity == "" || len(comments) == 0 || len(comments) > commentsMaxPerApp {
			return nil, ErrCommentThreadInvalid
		}
		for _, comment := range comments {
			if comment.ID == "" || ids[comment.ID] || comment.CreatedAt.IsZero() || strings.TrimSpace(comment.Text) == "" || utf8.RuneCountInString(comment.Text) > types.CommentMaxLength {
				return nil, ErrCommentStoredInvalid
			}
			ids[comment.ID] = true
		}
		total += len(comments)
	}
	if total > commentsMaxTotal {
		return nil, ErrCommentCapacity
	}
	voteTotal := 0
	for id, votes := range s.votes {
		if !ids[id] || len(votes) > 1024 {
			return nil, ErrCommentVotesInvalid
		}
		for voter, vote := range votes {
			if voter == "" || (vote != VoteUp && vote != VoteDown) {
				return nil, ErrCommentVoteInvalid
			}
		}
		voteTotal += len(votes)
	}
	if voteTotal > commentsMaxVotes {
		return nil, ErrCommentCapacity
	}
	for id, hash := range s.authors {
		if !ids[id] || hash == "" {
			return nil, ErrCommentAuthorInvalid
		}
	}
	return s, nil
}

func (s *CommentsStore) AllowPost(source netip.Addr) time.Duration {
	retry, _ := s.limiter.Allow(source, 1)
	return retry
}

func (s *CommentsStore) AllowVote(source netip.Addr) time.Duration {
	retry, _ := s.voteLimiter.Allow(source, 1)
	return retry
}

func (s *CommentsStore) List(identity, viewerHash, authorHash string) []types.AppComment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(identity, viewerHash, authorHash)
}

func (s *CommentsStore) Add(identity, text, viewerHash, authorHash string) ([]types.AppComment, error) {
	text = strings.TrimSpace(text)
	if identity == "" || authorHash == "" || text == "" || utf8.RuneCountInString(text) > types.CommentMaxLength {
		return nil, ErrCommentInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, comments := range s.threads {
		total += len(comments)
	}
	if total >= commentsMaxTotal || len(s.threads[identity]) >= commentsMaxPerApp {
		return nil, ErrCommentCapacity
	}
	comments := append([]types.AppComment{}, s.threads[identity]...)
	comment := types.AppComment{ID: rand.Text(), Text: text, CreatedAt: time.Now().UTC()}
	comments = append(comments, comment)
	next := maps.Clone(s.threads)
	next[identity] = comments
	nextAuthors := maps.Clone(s.authors)
	nextAuthors[comment.ID] = authorHash
	state := persistedComments{
		Threads: next,
		Votes:   s.votes,
		Authors: nextAuthors,
	}
	if err := utils.WriteJSONFile(s.path, state, 0o600); err != nil {
		return nil, fmt.Errorf("persist comment: %w", err)
	}
	s.threads = next
	s.authors = nextAuthors
	return s.listLocked(identity, viewerHash, authorHash), nil
}

func (s *CommentsStore) Delete(identity, id, viewerHash, authorHash string) ([]types.AppComment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authorHash == "" || s.authors[id] != authorHash {
		return nil, ErrCommentNotFound
	}
	comments := s.threads[identity]
	index := slices.IndexFunc(comments, func(comment types.AppComment) bool { return comment.ID == id })
	if index < 0 {
		return nil, ErrCommentNotFound
	}
	next := maps.Clone(s.threads)
	remaining := slices.Delete(slices.Clone(comments), index, index+1)
	if len(remaining) == 0 {
		delete(next, identity)
	} else {
		next[identity] = remaining
	}
	nextVotes := maps.Clone(s.votes)
	delete(nextVotes, id)
	nextAuthors := maps.Clone(s.authors)
	delete(nextAuthors, id)
	state := persistedComments{Threads: next, Votes: nextVotes, Authors: nextAuthors}
	if err := utils.WriteJSONFile(s.path, state, 0o600); err != nil {
		return nil, fmt.Errorf("delete comment: %w", err)
	}
	s.threads = next
	s.votes = nextVotes
	s.authors = nextAuthors
	return s.listLocked(identity, viewerHash, authorHash), nil
}

// Vote casts or clears an up/down vote for a comment from a verified voter hash.
func (s *CommentsStore) Vote(identity, id, vote, voterHash, authorHash string) ([]types.AppComment, error) {
	vote = strings.TrimSpace(vote)
	if vote != VoteUp && vote != VoteDown && vote != VoteClear {
		return nil, ErrCommentVoteChoice
	}
	if voterHash == "" {
		return nil, ErrCommentVoterRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !slices.ContainsFunc(s.threads[identity], func(c types.AppComment) bool { return c.ID == id }) {
		return nil, ErrCommentNotFound
	}
	previous := s.votes[id][voterHash]
	if previous == vote || (vote == VoteClear && previous == "") {
		return s.listLocked(identity, voterHash, authorHash), nil
	}

	nextVotes := maps.Clone(s.votes)
	commentVotes := maps.Clone(s.votes[id])
	if commentVotes == nil {
		commentVotes = make(map[string]string)
	}

	if vote == VoteClear {
		delete(commentVotes, voterHash)
		if len(commentVotes) == 0 {
			delete(nextVotes, id)
		} else {
			nextVotes[id] = commentVotes
		}
	} else {
		if _, exists := commentVotes[voterHash]; !exists && len(commentVotes) >= 1024 {
			return nil, ErrCommentCapacity
		}
		if _, exists := commentVotes[voterHash]; !exists {
			total := 0
			for _, votes := range s.votes {
				total += len(votes)
			}
			if total >= commentsMaxVotes {
				return nil, ErrCommentCapacity
			}
		}
		commentVotes[voterHash] = vote
		nextVotes[id] = commentVotes
	}

	state := persistedComments{
		Threads: s.threads,
		Votes:   nextVotes,
		Authors: s.authors,
	}
	if err := utils.WriteJSONFile(s.path, state, 0o600); err != nil {
		return nil, fmt.Errorf("persist comment vote: %w", err)
	}
	s.votes = nextVotes
	return s.listLocked(identity, voterHash, authorHash), nil
}

func (s *CommentsStore) listLocked(identity, viewerHash, authorHash string) []types.AppComment {
	raw := s.threads[identity]
	result := make([]types.AppComment, len(raw))
	for i, c := range raw {
		result[i] = s.enrichCommentLocked(c, viewerHash, authorHash)
	}
	return result
}

func (s *CommentsStore) enrichCommentLocked(comment types.AppComment, viewerHash, authorHash string) types.AppComment {
	votes := s.votes[comment.ID]
	up, down := 0, 0
	for _, v := range votes {
		switch v {
		case VoteUp:
			up++
		case VoteDown:
			down++
		}
	}
	comment.Up = up
	comment.Down = down
	comment.CanDelete = authorHash != "" && s.authors[comment.ID] == authorHash
	comment.ViewerVote = votes[viewerHash]
	return comment
}
