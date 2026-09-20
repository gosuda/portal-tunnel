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
	"maps"
	"math"
	"net/http"
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

	reputationVoterCookie  = "portal_voter"
	reputationVoterIDBytes = 32

	// Whole-file JSON is rewritten on each changed vote so these caps keep
	// the work per public POST small; identities persist for the life of
	// the state file, so past the identity cap new identities are rejected.
	reputationMaxVoters     = 64
	reputationMaxIdentities = 128
)

const (
	voteUp   = "up"
	voteDown = "down"
)

// persistedReputation is the reputation.json schema. All collections are
// bounded by the reputationMax* constants.
type persistedReputation struct {
	VoterSecret []byte                       `json:"voter_secret"`
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
)

// ReputationStore owns only the bounded vote ledger and voter cookie secret.
type ReputationStore struct {
	path    string
	limiter *policy.SourceLimiter

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
	store.limiter = policy.NewSourceLimiter(10, 20, 120, 40)
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
	nextIdentities := maps.Clone(s.state.Identities)
	votes := maps.Clone(previous)
	if votes == nil {
		votes = make(map[string]string)
	}
	if _, exists := votes[hash]; !exists && len(votes) >= reputationMaxVoters {
		return reputationSummary{}, "", errReputationCapacity
	}
	votes[hash] = vote
	nextIdentities[identity] = votes
	nextState := s.state
	nextState.Identities = nextIdentities

	if err := utils.WriteJSONFile(s.path, nextState, 0o600); err != nil {
		return reputationSummary{}, "", fmt.Errorf("persist reputation: %w", err)
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
	return rows
}

// viewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous; the cookieless mint path
// exists only on votes.
func (s *ReputationStore) viewerHashFor(cookieID string) string {
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
		return "", "", errReputationCapacity
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
func (s *ReputationStore) summarize(hostname string, votes map[string]string, viewerHash string) reputationSummary {
	if votes == nil {
		return reputationSummary{Hostname: hostname}
	}
	up, down := 0, 0
	for _, vote := range votes {
		switch vote {
		case voteUp:
			up++
		case voteDown:
			down++
		}
	}
	return reputationSummary{
		Hostname:   hostname,
		Up:         up,
		Down:       down,
		Total:      up + down,
		ViewerVote: votes[viewerHash],
	}
}

// serveReputationVote is admission -> decode -> store op. Admission runs
// before decoding, matching portal's admitPreAuth: rate-limited sources pay
// no parse cost, and the body bound applies inside decode.
func (api *RelayAPI) serveReputationVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	clientIP := api.server.PolicyRuntime().ExtractClientIP(r)
	if retry, _ := api.reputation.limiter.Allow(clientIP, 1); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote request budget exhausted")
		return
	}
	req, ok := utils.DecodeJSONRequestAs[reputationVoteRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	hostname := utils.NormalizeHostname(req.Hostname)
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
	for _, lease := range publicIdentityLeases(api.server.PublicLeases(), api.server) {
		if utils.NormalizeHostname(lease.Hostname) == hostname {
			identity = lease.IdentityKey
			break
		}
	}
	summary, minted, err := api.reputation.castVote(hostname, identity, vote, voterCookieID(r), clientIP)
	if err != nil {
		writeReputationError(w, err)
		return
	}
	if minted != "" {
		setVoterCookie(w, r, minted)
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}

func writeReputationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errReputationCapacity):
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
	case errors.Is(err, errReputationUnknownHostname):
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "hostname is not in the public directory")
	default:
		log.Error().Err(err).Msg("persist reputation vote")
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

func publicIdentityLeases(public []types.Lease, server *portal.Server) []types.PolicyLease {
	known := make(map[string]bool)
	for _, lease := range public {
		known[utils.NormalizeHostname(lease.Hostname)] = true
	}
	leases := make([]types.PolicyLease, 0)
	for _, lease := range server.PolicyLeases() {
		if known[utils.NormalizeHostname(lease.Hostname)] && lease.IdentityKey != "" {
			leases = append(leases, lease)
		}
	}
	return leases
}
