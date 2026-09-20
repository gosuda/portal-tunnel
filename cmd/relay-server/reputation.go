package main

// Service reputation: relay-local, stable-identity-keyed up/down votes.
//
// The relay's lease registry owns service lifecycle. This file only maps a
// current public hostname to its stable identity and stores that identity's
// bounded voter ledger. portal.Server and shared lease types stay unchanged.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// Relay-local wire paths. Deliberately not in types/paths.go: no Go
	// package outside cmd/relay-server needs them.
	pathReputationVote = types.PathAPIPrefix + "/reputation/vote"

	reputationFilename = "reputation.json"

	// reputationVoterCookie carries "hex(id).hex(HMAC(secret, id))". The raw
	// id is never stored; only its digest enters the persisted state.
	reputationVoterCookie  = "portal_voter"
	reputationBodyLimit    = 1 << 12
	reputationVoterIDBytes = 32

	// Vote admission budgets. Fixed constants, not knobs: they are abuse
	// bounds, not product behavior (see issue #472 MVP scope).
	reputationVoteSourcePerMinute = 10
	reputationVoteSourceBurst     = 20
	reputationVoteGlobalPerMinute = 120
	reputationVoteGlobalBurst     = 40
	reputationVoteMintCost        = 10

	// Whole-file JSON is written on each changed vote, so these caps keep
	// the work per public POST small.
	reputationMaxIdentities = 128
	reputationMaxVoters     = 64
)

const (
	voteUp   = "up"
	voteDown = "down"
)

// persistedReputation is the reputation.json schema. All collections are
// bounded by the reputationMax* constants.
type persistedReputation struct {
	VoterSecret string                       `json:"voter_secret"`
	Identities  map[string]map[string]string `json:"identities,omitempty"`
}

// Wire contracts. Local to the relay on purpose; the frontend mirrors them.
type reputationVoteRequest struct {
	Hostname string `json:"hostname"`
	Vote     string `json:"vote"`
}

type reputationSummary struct {
	Hostname   string `json:"hostname"`
	Up         int    `json:"up"`
	Down       int    `json:"down"`
	Total      int    `json:"total"`
	ViewerVote string `json:"viewer_vote"` // "" | "up" | "down"
}

var (
	errReputationUnknownHostname = errors.New("hostname is not in the public directory")
	errReputationCapacity        = errors.New("reputation capacity exhausted")
	errReputationPersist         = errors.New("reputation persist failed")
)

// ReputationStore owns only the bounded vote ledger and voter cookie secret.
type ReputationStore struct {
	path    string
	limiter *policy.SourceLimiter

	// persistFn writes the persisted state; a field so tests can swap in a
	// failing closure and prove the rollback path.
	persistFn func(persistedReputation) error

	mu     sync.Mutex
	state  persistedReputation
	secret []byte
}

func newReputationStore(path string) (*ReputationStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("reputation store requires a state path")
	}
	store := &ReputationStore{path: path}
	loaded, err := utils.ReadJSONFileIfExists(path, &store.state)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if store.state.Identities == nil {
		store.state.Identities = make(map[string]map[string]string)
	}
	secretGenerated := false
	var secret []byte
	if store.state.VoterSecret != "" {
		secret, err = base64.StdEncoding.DecodeString(store.state.VoterSecret)
		if err != nil {
			return nil, fmt.Errorf("load reputation voter secret: %w", err)
		}
	}
	if len(secret) == 0 {
		secret = make([]byte, reputationVoterIDBytes)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate reputation voter secret: %w", err)
		}
		store.state.VoterSecret = base64.StdEncoding.EncodeToString(secret)
		secretGenerated = true
	}
	store.secret = secret
	store.limiter = policy.NewSourceLimiter(reputationVoteSourcePerMinute, reputationVoteSourceBurst, reputationVoteGlobalPerMinute, reputationVoteGlobalBurst)
	store.persistFn = func(state persistedReputation) error { return utils.WriteJSONFile(store.path, state, 0o600) }
	if secretGenerated {
		// The secret anchors every voter hash; persist it before the first
		// mint so voter identity is restart-stable from the start.
		if err := store.persistFn(store.state); err != nil {
			return nil, fmt.Errorf("persist reputation voter secret: %w", err)
		}
	}
	if loaded {
		log.Info().Str("path", path).Int("identities", len(store.state.Identities)).Msg("restored service reputation")
	}
	return store, nil
}

// castVote resolves the voter (minting a cookieless identity when needed),
// applies the vote, and persists atomically under one lock. The returned
// mint value is a fresh cookie value, set only when a new voter was minted.
// The identity comes from the relay's current public leases.
func (s *ReputationStore) castVote(hostname, identity, vote, cookieID, source string) (reputationSummary, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity == "" {
		return reputationSummary{}, "", errReputationUnknownHostname
	}
	hash, minted, err := s.resolveVoterLocked(cookieID, source)
	if err != nil {
		return reputationSummary{}, "", err
	}

	previous := s.state.Identities[identity]
	if previous != nil && previous[hash] == vote {
		return s.summarize(hostname, previous, hash), minted, nil
	}
	if previous == nil && len(s.state.Identities) >= reputationMaxIdentities {
		return reputationSummary{}, "", errReputationCapacity
	}
	nextIdentities := make(map[string]map[string]string, len(s.state.Identities)+1)
	for key, votes := range s.state.Identities {
		nextIdentities[key] = votes
	}
	votes := make(map[string]string, len(previous)+1)
	for voter, existing := range previous {
		votes[voter] = existing
	}
	if _, exists := votes[hash]; !exists && len(votes) >= reputationMaxVoters {
		return reputationSummary{}, "", errReputationCapacity
	}
	votes[hash] = vote
	nextIdentities[identity] = votes
	nextState := s.state
	nextState.Identities = nextIdentities

	if err := s.persistFn(nextState); err != nil {
		return reputationSummary{}, "", fmt.Errorf("%w: %w", errReputationPersist, err)
	}
	s.state = nextState
	return s.summarize(hostname, votes, hash), minted, nil
}

func (s *ReputationStore) summaries(viewerHash string, leases []types.PolicyLease) []reputationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]reputationSummary, 0, len(leases))
	for _, lease := range leases {
		rows = append(rows, s.summarize(lease.Hostname, s.state.Identities[lease.IdentityKey], viewerHash))
	}
	slices.SortFunc(rows, func(a, b reputationSummary) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return rows
}

// viewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous; the cookieless mint path
// exists only on votes.
func (s *ReputationStore) viewerHashFor(cookieID string) string {
	if cookieID == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.verifyVoterLocked(cookieID)
	if !ok {
		return ""
	}
	return hash
}

// resolveVoterLocked returns the digest for a verified cookie or mints a new
// cookieless identity. Signed cookies need no persisted global voter registry.
func (s *ReputationStore) resolveVoterLocked(cookieID, source string) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoterLocked(cookieID); ok {
			return verified, "", nil
		}
	}
	if retry, _ := s.limiter.Allow(source, reputationVoteMintCost); retry > 0 {
		return "", "", errReputationCapacity
	}
	id := make([]byte, reputationVoterIDBytes)
	if _, err := rand.Read(id); err != nil {
		return "", "", fmt.Errorf("generate voter id: %w", err)
	}
	digest := s.voterMAC(id)
	hash = hex.EncodeToString(digest)
	return hash, hex.EncodeToString(id) + "." + hash, nil
}

// verifyVoterLocked validates "hex(id).hex(mac)" under the store secret.
// Callers hold the mutex: the secret is read from shared state here.
func (s *ReputationStore) verifyVoterLocked(cookieID string) (string, bool) {
	idHex, macHex, ok := strings.Cut(cookieID, ".")
	if !ok {
		return "", false
	}
	id, err := hex.DecodeString(idHex)
	if err != nil || len(id) != reputationVoterIDBytes {
		return "", false
	}
	mac, err := hex.DecodeString(macHex)
	if err != nil || len(mac) != sha256.Size {
		return "", false
	}
	expected := s.voterMAC(id)
	if subtle.ConstantTimeCompare(expected, mac) != 1 {
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
func (s *ReputationStore) summarize(hostname string, votes map[string]string, viewerHash string) reputationSummary {
	if votes == nil {
		return reputationSummary{Hostname: hostname}
	}
	up, down := tallyVotes(votes)
	return reputationSummary{
		Hostname:   hostname,
		Up:         up,
		Down:       down,
		Total:      up + down,
		ViewerVote: votes[viewerHash],
	}
}

func tallyVotes(votes map[string]string) (up, down int) {
	for _, vote := range votes {
		switch vote {
		case voteUp:
			up++
		case voteDown:
			down++
		}
	}
	return up, down
}

// serveReputationVote is admission -> decode -> store op. Admission runs
// before decoding, matching portal's admitPreAuth: rate-limited sources pay
// no parse cost, and the body bound applies inside decode.
func (api *RelayAPI) serveReputationVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !api.admitReputationVote(w, r) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[reputationVoteRequest](w, r, reputationBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	hostname := normalizeReputationHostname(req.Hostname)
	if hostname == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "hostname is required")
		return
	}
	vote := strings.TrimSpace(req.Vote)
	if vote != voteUp && vote != voteDown {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "vote must be 'up' or 'down'")
		return
	}
	identity := ""
	for _, lease := range publicIdentityLeases(api.server) {
		if normalizeReputationHostname(lease.Hostname) == hostname {
			identity = lease.IdentityKey
			break
		}
	}
	summary, minted, err := api.reputation.castVote(hostname, identity, vote, voterCookieID(r), api.server.PolicyRuntime().ExtractClientIP(r))
	if err != nil {
		writeReputationError(w, err)
		return
	}
	if minted != "" {
		setVoterCookie(w, r, minted)
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}

// admitReputationVote bounds vote traffic with the same SourceLimiter shape
// the pre-auth admission uses: per-source and global token buckets over the
// client IP, before any decode work.
func (api *RelayAPI) admitReputationVote(w http.ResponseWriter, r *http.Request) bool {
	clientIP := api.server.PolicyRuntime().ExtractClientIP(r)
	retry, _ := api.reputation.limiter.Allow(clientIP, 1)
	if retry == 0 {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote request budget exhausted")
	return false
}

func writeReputationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errReputationCapacity):
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
	case errors.Is(err, errReputationUnknownHostname):
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "hostname is not in the public directory")
	case errors.Is(err, errReputationPersist):
		log.Error().Err(err).Msg("persist reputation vote")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "reputation could not be persisted")
	default:
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "vote failed")
	}
}

// voterCookieID only reads the cookie; parsing and verification belong to the store.
func voterCookieID(r *http.Request) string {
	cookie, err := r.Cookie(reputationVoterCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setVoterCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     reputationVoterCookie,
		Value:    value,
		Path:     types.PathAPIPrefix,
		MaxAge:   int((10 * 365 * 24 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func normalizeReputationHostname(raw string) string {
	hostname := strings.ToLower(strings.TrimSpace(raw))
	if hostname == "" || len(hostname) > 253 {
		return ""
	}
	return hostname
}

func publicIdentityLeases(server *portal.Server) []types.PolicyLease {
	public := make(map[string]bool)
	for _, lease := range server.PublicLeases() {
		public[normalizeReputationHostname(lease.Hostname)] = true
	}
	leases := make([]types.PolicyLease, 0)
	for _, lease := range server.PolicyLeases() {
		if public[normalizeReputationHostname(lease.Hostname)] && lease.IdentityKey != "" {
			leases = append(leases, lease)
		}
	}
	return leases
}
