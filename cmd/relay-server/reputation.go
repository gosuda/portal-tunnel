package main

// Service reputation: relay-local, hostname-keyed up/down votes.
//
// Ownership rules enforced by this file:
//   - Records key on the relay-local public hostname ??never the lease ID and
//     never an identity key ??so reputation survives re-registration.
//   - portal.Server stays unaware of reputation. No lease callbacks or
//     background reconciliation; new hosts are admitted from the public
//     directory at the vote boundary.
//   - The directory projection is a dedicated endpoint (GET /api/reputation),
//     not extra fields on types.Lease: reputation is relay-local and types/
//     stays free of reputation concepts. The frontend joins rows with
//     /api/state by hostname and mirrors the two paths below in
//     frontend/src/lib/apiPaths.ts.
//   - Voters and client sources are stored only as HMAC digests; no raw IP or
//     voter ID is ever persisted.

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
	pathReputation     = types.PathAPIPrefix + "/reputation"
	pathReputationVote = pathReputation + "/vote"

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

	// Whole-file JSON is written on each changed vote, so these caps keep
	// the work per public POST small.
	reputationMaxHostnames         = 128
	reputationMaxVotersPerHostname = 64
)

const (
	voteUp   = "up"
	voteDown = "down"
)

// ReputationConfig controls how long an absent hostname remains visible.
type ReputationConfig struct {
	Retention time.Duration
}

func defaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		Retention: 720 * time.Hour,
	}
}

func (c ReputationConfig) validate() error {
	if c.Retention <= 0 {
		return errors.New("reputation retention must be positive")
	}
	return nil
}

// reputationRecord is one hostname's vote tally and last activity.
// Up/down are derived from Voters at read time so counters cannot drift.
type reputationRecord struct {
	LastSeenAt time.Time         `json:"last_seen_at"`
	Voters     map[string]string `json:"voters"`
}

// persistedReputation is the reputation.json schema. All collections are
// bounded by the reputationMax* constants.
type persistedReputation struct {
	VoterSecret string                       `json:"voter_secret"`
	Hostnames   map[string]*reputationRecord `json:"hostnames,omitempty"`
}

// Wire contracts. Local to the relay on purpose; the frontend mirrors them.
type reputationVoteRequest struct {
	Hostname string `json:"hostname"`
	Vote     string `json:"vote"`
}

type reputationSummary struct {
	Up         int    `json:"up"`
	Down       int    `json:"down"`
	Total      int    `json:"total"`
	ViewerVote string `json:"viewer_vote"` // "" | "up" | "down"
}

type reputationDirectoryRow struct {
	Hostname  string  `json:"hostname"`
	Up        int     `json:"up"`
	Down      int     `json:"down"`
	Total     int     `json:"total"`
}

type reputationDirectory struct {
	Hostnames []reputationDirectoryRow `json:"hostnames"`
}

var (
	errReputationUnknownHostname  = errors.New("hostname is not in the public directory")
	errReputationHostnameCapacity = errors.New("hostname capacity exhausted")
	errReputationVoterCapacity    = errors.New("hostname voter capacity exhausted")
	errReputationPersist          = errors.New("reputation persist failed")
)

// ReputationStore is the single owner of relay-local service reputation. One
// mutex covers resolve/mint/apply/persist and each mutation has local rollback.
type ReputationStore struct {
	path    string
	cfg     ReputationConfig
	limiter *policy.SourceLimiter
	now     func() time.Time

	// persistFn writes the persisted state; a field so tests can swap in a
	// failing closure and prove the rollback path.
	persistFn func() error

	mu     sync.Mutex
	state  persistedReputation
	secret []byte
}

func newReputationStore(path string, cfg ReputationConfig) (*ReputationStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("reputation store requires a state path")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	store := &ReputationStore{path: path, cfg: cfg, now: time.Now}
	loaded, err := utils.ReadJSONFileIfExists(path, &store.state)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if store.state.Hostnames == nil {
		store.state.Hostnames = make(map[string]*reputationRecord)
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
	store.persistFn = func() error { return utils.WriteJSONFile(store.path, store.state, 0o600) }
	if secretGenerated {
		// The secret anchors every voter hash; persist it before the first
		// mint so voter identity is restart-stable from the start.
		if err := store.persistFn(); err != nil {
			return nil, fmt.Errorf("persist reputation voter secret: %w", err)
		}
	}
	if loaded {
		log.Info().Str("path", path).Int("hostnames", len(store.state.Hostnames)).Msg("restored service reputation")
	}
	return store, nil
}

// castVote resolves the voter (minting a cookieless identity when needed),
// applies the vote, and persists atomically under one lock. The returned
// mint value is a fresh cookie value, set only when a new voter was minted.
// known reports whether the hostname currently appears in the public directory.
func (s *ReputationStore) castVote(hostname, vote, cookieID string, live map[string]bool) (reputationSummary, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, minted, err := s.resolveVoterLocked(cookieID)
	if err != nil {
		return reputationSummary{}, "", err
	}

	now := s.now().UTC()
	previous := s.state.Hostnames[hostname]
	if previous == nil && !live[hostname] {
		return reputationSummary{}, "", errReputationUnknownHostname
	}
	if previous != nil && (live[hostname] || now.Sub(previous.LastSeenAt) <= s.cfg.Retention) && previous.Voters[hash] == vote {
		return s.summarize(previous, hash), minted, nil
	}
	var evictedHost string
	var evictedRecord *reputationRecord
	if previous == nil && len(s.state.Hostnames) >= reputationMaxHostnames {
		for candidate, rec := range s.state.Hostnames {
			if !live[candidate] && now.Sub(rec.LastSeenAt) > s.cfg.Retention && (evictedRecord == nil || rec.LastSeenAt.Before(evictedRecord.LastSeenAt)) {
				evictedHost, evictedRecord = candidate, rec
			}
		}
		if evictedRecord == nil {
			return reputationSummary{}, "", errReputationHostnameCapacity
		}
	}
	if previous != nil && !live[hostname] && now.Sub(previous.LastSeenAt) > s.cfg.Retention {
		return reputationSummary{}, "", errReputationUnknownHostname
	}
	if previous == nil {
		if evictedRecord != nil {
			delete(s.state.Hostnames, evictedHost)
		}
		s.state.Hostnames[hostname] = &reputationRecord{Voters: make(map[string]string)}
	}
	rec := s.state.Hostnames[hostname]
	if _, exists := rec.Voters[hash]; !exists && len(rec.Voters) >= reputationMaxVotersPerHostname {
		if previous == nil {
			delete(s.state.Hostnames, hostname)
		} else {
			s.state.Hostnames[hostname] = previous
		}
		if evictedRecord != nil {
			s.state.Hostnames[evictedHost] = evictedRecord
		}
		return reputationSummary{}, "", errReputationVoterCapacity
	}
	var oldVote string
	var oldSeen time.Time
	if previous == rec {
		oldVote = rec.Voters[hash]
		oldSeen = rec.LastSeenAt
	}
	rec.Voters[hash] = vote
	rec.LastSeenAt = now

	if err := s.persistFn(); err != nil {
		if previous != rec {
			if previous == nil {
				delete(s.state.Hostnames, hostname)
			} else {
				s.state.Hostnames[hostname] = previous
			}
			if evictedRecord != nil {
				s.state.Hostnames[evictedHost] = evictedRecord
			}
		} else {
			if oldVote == "" {
				delete(rec.Voters, hash)
			} else {
				rec.Voters[hash] = oldVote
			}
			rec.LastSeenAt = oldSeen
		}
		return reputationSummary{}, "", fmt.Errorf("%w: %w", errReputationPersist, err)
	}
	return s.summarize(rec, hash), minted, nil
}

// summary is the read-side single-hostname view. Reads never mutate: an
// expired record returns an empty summary without being deleted.
func (s *ReputationStore) summary(hostname, viewerHash string, live map[string]bool) reputationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.state.Hostnames[hostname]
	if rec == nil || !s.visibleLocked(hostname, rec, live) {
		return reputationSummary{}
	}
	return s.summarize(rec, viewerHash)
}

// directory is the hostname-keyed aggregate projection for the directory
// list, sorted for deterministic output.
func (s *ReputationStore) directory(live map[string]bool) reputationDirectory {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]reputationDirectoryRow, 0, len(s.state.Hostnames))
	for hostname, rec := range s.state.Hostnames {
		if !s.visibleLocked(hostname, rec, live) {
			continue
		}
		up, down := tallyVotes(rec)
		rows = append(rows, reputationDirectoryRow{Hostname: hostname, Up: up, Down: down, Total: up + down})
	}
	slices.SortFunc(rows, func(a, b reputationDirectoryRow) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return reputationDirectory{Hostnames: rows}
}

// viewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous ??the cookieless mint path
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
func (s *ReputationStore) resolveVoterLocked(cookieID string) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoterLocked(cookieID); ok {
			return verified, "", nil
		}
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

// visibleLocked implements the retention read rule: a record stays visible
// while fresh, or while its hostname is currently live. A long-absent
// hostname (stale and not live) drops out of reads without deleting the
// record; admission deletes it when the hostname is voted again.
func (s *ReputationStore) visibleLocked(hostname string, rec *reputationRecord, live map[string]bool) bool {
	if live[hostname] {
		return true
	}
	return s.now().Sub(rec.LastSeenAt) <= s.cfg.Retention
}

func (s *ReputationStore) summarize(rec *reputationRecord, viewerHash string) reputationSummary {
	up, down := tallyVotes(rec)
	return reputationSummary{
		Up:         up,
		Down:       down,
		Total:      up + down,
		ViewerVote: rec.Voters[viewerHash],
	}
}

func tallyVotes(rec *reputationRecord) (up, down int) {
	for _, vote := range rec.Voters {
		switch vote {
		case voteUp:
			up++
		case voteDown:
			down++
		}
	}
	return up, down
}

// ??? HTTP handlers ???????????????????????????????????????????????????????????

// serveReputation serves the directory projection (no query) or one
// hostname's summary (hostname=...). Pure reads: no cookie is minted and no
// store state changes.
func (api *RelayAPI) serveReputation(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	live := liveHostnames(api.server)
	viewerHash := api.reputation.viewerHashFor(voterCookieID(r))
	if hostname := normalizeReputationHostname(r.URL.Query().Get("hostname")); hostname != "" {
		utils.WriteAPIData(w, http.StatusOK, api.reputation.summary(hostname, viewerHash, live))
		return
	}
	utils.WriteAPIData(w, http.StatusOK, api.reputation.directory(live))
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
	summary, minted, err := api.reputation.castVote(hostname, vote, voterCookieID(r), liveHostnames(api.server))
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
	case errors.Is(err, errReputationHostnameCapacity),
		errors.Is(err, errReputationVoterCapacity):
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

// voterCookieID returns the cookie value when it is structurally valid, else
// "". MAC verification needs the store secret and happens under the store
// lock; a structurally valid but forged cookie degrades to the cookieless
// mint path there.
func voterCookieID(r *http.Request) string {
	cookie, err := r.Cookie(reputationVoterCookie)
	if err != nil || cookie.Value == "" {
		return ""
	}
	idHex, macHex, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return ""
	}
	id, err := hex.DecodeString(idHex)
	if err != nil || len(id) != reputationVoterIDBytes {
		return ""
	}
	mac, err := hex.DecodeString(macHex)
	if err != nil || len(mac) != sha256.Size {
		return ""
	}
	return cookie.Value
}

func setVoterCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     reputationVoterCookie,
		Value:    value,
		Path:     pathReputation,
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

func liveHostnames(server *portal.Server) map[string]bool {
	live := make(map[string]bool)
	for _, lease := range server.PublicLeases() {
		if hostname := normalizeReputationHostname(lease.Hostname); hostname != "" {
			live[hostname] = true
		}
	}
	return live
}

