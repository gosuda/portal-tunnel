package policy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
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
	ErrCommentInvalid       = errors.New("comment must contain 1 to 2000 characters")
	ErrCommentCapacity      = errors.New("comment storage limit reached")
	ErrCommentNotFound      = errors.New("comment not found")
	ErrCommentThreadInvalid = errors.New("invalid comment thread")
	ErrCommentStoredInvalid = errors.New("invalid stored comment")
	ErrCommentVotesInvalid  = errors.New("invalid comment votes")
	ErrCommentVoteInvalid   = errors.New("invalid comment vote")
	ErrCommentAuthorInvalid = errors.New("invalid comment author")
)

type storedComment struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

type persistedComments struct {
	Threads map[string][]storedComment   `json:"threads,omitempty"`
	Votes   map[string]map[string]string `json:"votes,omitempty"`
	Authors map[string]string            `json:"authors,omitempty"`
}

func (s *ReputationStore) validateComments() error {
	total := 0
	ids := make(map[string]bool)
	for identity, comments := range s.state.Comments.Threads {
		if identity == "" || len(comments) == 0 || len(comments) > commentsMaxPerApp {
			return ErrCommentThreadInvalid
		}
		for _, comment := range comments {
			if comment.ID == "" || ids[comment.ID] || comment.CreatedAt.IsZero() || strings.TrimSpace(comment.Text) == "" || utf8.RuneCountInString(comment.Text) > types.CommentMaxLength {
				return ErrCommentStoredInvalid
			}
			ids[comment.ID] = true
		}
		total += len(comments)
	}
	if total > commentsMaxTotal {
		return ErrCommentCapacity
	}
	voteTotal := 0
	for id, votes := range s.state.Comments.Votes {
		if !ids[id] || len(votes) > reputationMaxVoters {
			return ErrCommentVotesInvalid
		}
		for voter, vote := range votes {
			if voter == "" || (vote != VoteUp && vote != VoteDown) {
				return ErrCommentVoteInvalid
			}
		}
		voteTotal += len(votes)
	}
	if voteTotal > commentsMaxVotes {
		return ErrCommentCapacity
	}
	for id, hash := range s.state.Comments.Authors {
		if !ids[id] || hash == "" {
			return ErrCommentAuthorInvalid
		}
	}
	return nil
}

func (s *ReputationStore) AllowCommentPost(source netip.Addr) time.Duration {
	retry, _ := s.commentPostLimiter.Allow(source, 1)
	return retry
}

func (s *ReputationStore) ListComments(identity, viewerHash, authorHash string) []types.AppComment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(identity, viewerHash, authorHash)
}

func (s *ReputationStore) AddComment(identity, text, viewerHash, authorHash string) ([]types.AppComment, error) {
	text = strings.TrimSpace(text)
	if identity == "" || authorHash == "" || text == "" || utf8.RuneCountInString(text) > types.CommentMaxLength {
		return nil, ErrCommentInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, comments := range s.state.Comments.Threads {
		total += len(comments)
	}
	if total >= commentsMaxTotal || len(s.state.Comments.Threads[identity]) >= commentsMaxPerApp {
		return nil, ErrCommentCapacity
	}
	comments := append([]storedComment{}, s.state.Comments.Threads[identity]...)
	comment := storedComment{ID: rand.Text(), Text: text, CreatedAt: time.Now().UTC()}
	comments = append(comments, comment)
	next := maps.Clone(s.state.Comments.Threads)
	next[identity] = comments
	nextAuthors := maps.Clone(s.state.Comments.Authors)
	nextAuthors[comment.ID] = authorHash
	nextState := s.state
	state := persistedComments{
		Threads: next,
		Votes:   s.state.Comments.Votes,
		Authors: nextAuthors,
	}
	nextState.Comments = &state
	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return nil, fmt.Errorf("persist comment: %w", err)
	}
	s.state = nextState
	return s.listLocked(identity, viewerHash, authorHash), nil
}

func (s *ReputationStore) DeleteComment(identity, id, viewerHash, authorHash string) ([]types.AppComment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authorHash == "" || s.state.Comments.Authors[id] != authorHash {
		return nil, ErrCommentNotFound
	}
	comments := s.state.Comments.Threads[identity]
	index := slices.IndexFunc(comments, func(comment storedComment) bool { return comment.ID == id })
	if index < 0 {
		return nil, ErrCommentNotFound
	}
	next := maps.Clone(s.state.Comments.Threads)
	remaining := slices.Delete(slices.Clone(comments), index, index+1)
	if len(remaining) == 0 {
		delete(next, identity)
	} else {
		next[identity] = remaining
	}
	nextVotes := maps.Clone(s.state.Comments.Votes)
	delete(nextVotes, id)
	nextAuthors := maps.Clone(s.state.Comments.Authors)
	delete(nextAuthors, id)
	nextState := s.state
	state := persistedComments{Threads: next, Votes: nextVotes, Authors: nextAuthors}
	nextState.Comments = &state
	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return nil, fmt.Errorf("delete comment: %w", err)
	}
	s.state = nextState
	return s.listLocked(identity, viewerHash, authorHash), nil
}

func (s *ReputationStore) listLocked(identity, viewerHash, authorHash string) []types.AppComment {
	raw := s.state.Comments.Threads[identity]
	result := make([]types.AppComment, len(raw))
	for i, comment := range raw {
		summary := summarizeVotes(s.state.Comments.Votes[comment.ID], viewerHash)
		result[i] = types.AppComment{
			ID: comment.ID, Text: comment.Text, CreatedAt: comment.CreatedAt,
			Up: summary.Up, Down: summary.Down, ViewerVote: summary.ViewerVote,
			CanDelete: authorHash != "" && s.state.Comments.Authors[comment.ID] == authorHash,
		}
	}
	return result
}
