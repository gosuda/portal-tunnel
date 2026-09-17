package main

// Service reputation: relay-local, hostname-keyed up/down votes with a
// directory warning gate (issue #472 MVP).
//
// Ownership rules enforced by this file:
//   - Records key on the relay-local public hostname — never the lease ID and
//     never an identity key — so reputation survives re-registration.
//   - portal.Server stays unaware of reputation. Owner/first-seen observation
//     rides the explicit vote-admission boundary only: one PolicyLeases lookup
//     per vote. No lease callbacks, no background reconcile, no GET side
//     effects.
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
	"maps"
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

	// Persistence bounds. The persisted JSON stays bounded by these caps;
	// eviction rules below keep the caps honest.
	reputationMaxHostnames         = 4096
	reputationMaxVoters            = 4096
	reputationMaxVotersPerHostname = 512
)

const (
	voteUp   = "up"
	voteDown = "down"
)

// ReputationConfig carries the warning-threshold knobs. Retention also lives
// here: it governs when long-absent hostnames drop out of reputation.
type ReputationConfig struct {
	WarningMinTotal     int
	WarningMinDown      int
	WarningDownRatioPct int
	Retention           time.Duration
}

func defaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		WarningMinTotal:     5,
		WarningMinDown:      3,
		WarningDownRatioPct: 70,
		Retention:           720 * time.Hour,
	}
}

func (c ReputationConfig) validate() error {
	switch {
	case c.WarningMinTotal < 1:
		return errors.New("reputation warning min total must be at least 1")
	case c.WarningMinDown < 0:
		return errors.New("reputation warning min down must be non-negative")
	case c.WarningDownRatioPct < 0 || c.WarningDownRatioPct > 100:
		return errors.New("reputation warning down ratio must be 0-100 percent")
	case c.Retention <= 0:
		return errors.New("reputation retention must be positive")
	}
	return nil
}

// warning reports whether the directory warning gate holds for an aggregate.
// Integer math keeps the ratio boundary exact (3/5 at 50% is 300 >= 250).
func (c ReputationConfig) warning(total, down int) bool {
	return total >= c.WarningMinTotal && down >= c.WarningMinDown && down*100 >= total*c.WarningDownRatioPct
}

// reputationRecord is one hostname's vote tally and boundary observations.
// Up/down are derived from Voters at read time so counters cannot drift.
type reputationRecord struct {
	FirstSeenAt  time.Time         `json:"first_seen_at"`
	LastSeenAt   time.Time         `json:"last_seen_at"`
	OwnerKey     string            `json:"owner_key,omitempty"`
	KeyChangedAt time.Time         `json:"key_changed_at,omitempty"`
	Voters       map[string]string `json:"voters"`
}

func (r *reputationRecord) copy() *reputationRecord {
	clone := *r
	clone.Voters = make(map[string]string, len(r.Voters))
	maps.Copy(clone.Voters, r.Voters)
	return &clone
}

// persistedReputation is the reputation.json schema. All collections are
// bounded by the reputationMax* constants.
type persistedReputation struct {
	VoterSecret string                       `json:"voter_secret"`
	Voters      map[string]bool              `json:"voters,omitempty"`
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
	DownRatio float64 `json:"down_ratio"`
	Warning   bool    `json:"warning"`
}

type reputationDirectory struct {
	Hostnames []reputationDirectoryRow `json:"hostnames"`
}

var (
	errReputationVoterBudget      = errors.New("cookieless voter budget exhausted")
	errReputationHostnameCapacity = errors.New("hostname capacity exhausted")
	errReputationVoterCapacity    = errors.New("hostname voter capacity exhausted")
	errReputationPersist          = errors.New("reputation persist failed")
)

// ReputationStore is the single owner of relay-local service reputation. One
// mutex covers resolve/mint/apply/persist so a cookieless mint reserves its
// budget slot atomically and persist failures roll back to a clean snapshot.
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
	if store.state.Voters == nil {
		store.state.Voters = make(map[string]bool)
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
// ownerKey/ownerLive describe the hostname's current lease, observed once at
// this admission boundary.
func (s *ReputationStore) castVote(hostname, vote, cookieID, ownerKey string, ownerLive bool) (reputationSummary, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Snapshot before any mutation: a persist failure restores votes,
	// observations, and mint reservations to this pre-request state.
	snapshot := s.snapshotLocked()

	hash, minted, err := s.resolveVoterLocked(cookieID)
	if err != nil {
		return reputationSummary{}, "", err
	}
	// A cookieless mint reserved a budget slot; every pre-persist failure
	// rolls it back (delete on a missing key is a no-op).
	rollbackMint := func() {
		if minted != "" {
			delete(s.state.Voters, hash)
		}
	}

	now := s.now().UTC()
	rec := s.admitHostnameLocked(hostname, now)
	if rec == nil {
		rollbackMint()
		return reputationSummary{}, "", errReputationHostnameCapacity
	}
	if _, exists := rec.Voters[hash]; !exists && len(rec.Voters) >= reputationMaxVotersPerHostname {
		rollbackMint()
		return reputationSummary{}, "", errReputationVoterCapacity
	}

	if ownerLive {
		if rec.OwnerKey != "" && rec.OwnerKey != ownerKey {
			rec.KeyChangedAt = now
		}
		rec.OwnerKey = ownerKey
	}
	rec.Voters[hash] = vote
	rec.LastSeenAt = now

	if err := s.persistFn(); err != nil {
		s.state = snapshot
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
		rows = append(rows, reputationDirectoryRow{
			Hostname:  hostname,
			Up:        up,
			Down:      down,
			Total:     up + down,
			DownRatio: downRatio(up+down, down),
			Warning:   s.cfg.warning(up+down, down),
		})
	}
	slices.SortFunc(rows, func(a, b reputationDirectoryRow) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return reputationDirectory{Hostnames: rows}
}

// viewerHashFor resolves a cookie to its voter digest for read paths. A
// forged or malformed cookie reads as anonymous — the cookieless mint path
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
// cookieless identity. The mint checks and reserves its budget slot while
// the caller holds the mutex; callers roll the reservation back on failure.
func (s *ReputationStore) resolveVoterLocked(cookieID string) (hash, minted string, err error) {
	if cookieID != "" {
		if verified, ok := s.verifyVoterLocked(cookieID); ok {
			// Re-enter the budget registry: a verified voter whose row went
			// missing (hand-restored state) must still count against the cap.
			s.state.Voters[verified] = true
			return verified, "", nil
		}
	}
	if len(s.state.Voters) >= reputationMaxVoters {
		return "", "", errReputationVoterBudget
	}
	id := make([]byte, reputationVoterIDBytes)
	if _, err := rand.Read(id); err != nil {
		return "", "", fmt.Errorf("generate voter id: %w", err)
	}
	digest := s.voterMAC(id)
	hash = hex.EncodeToString(digest)
	s.state.Voters[hash] = true
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

// admitHostnameLocked returns the mutable record for hostname, applying the
// admission-time retention rule: an expired record restarts fresh. When the
// store is at capacity it evicts one admissible record — never a voted,
// fresh one — and returns nil when nothing is evictable.
func (s *ReputationStore) admitHostnameLocked(hostname string, now time.Time) *reputationRecord {
	if rec := s.state.Hostnames[hostname]; rec != nil {
		if now.Sub(rec.LastSeenAt) > s.cfg.Retention {
			rec = &reputationRecord{FirstSeenAt: now, LastSeenAt: now, Voters: map[string]string{}}
			s.state.Hostnames[hostname] = rec
			return rec
		}
		rec.LastSeenAt = now
		return rec
	}
	if len(s.state.Hostnames) >= reputationMaxHostnames && !s.evictAdmissibleLocked(now) {
		return nil
	}
	rec := &reputationRecord{FirstSeenAt: now, LastSeenAt: now, Voters: map[string]string{}}
	s.state.Hostnames[hostname] = rec
	return rec
}

// evictAdmissibleLocked frees one slot at the hostname cap. Voteless records
// go first (oldest seen); only records already past retention may otherwise
// be evicted — a voted, fresh record is never dropped for a newcomer, which
// is what blocks reputation-reset griefing.
func (s *ReputationStore) evictAdmissibleLocked(now time.Time) bool {
	bestVoteless, bestExpired := "", ""
	for hostname, rec := range s.state.Hostnames {
		if len(rec.Voters) == 0 {
			if bestVoteless == "" || rec.LastSeenAt.Before(s.state.Hostnames[bestVoteless].LastSeenAt) {
				bestVoteless = hostname
			}
			continue
		}
		if now.Sub(rec.LastSeenAt) > s.cfg.Retention && (bestExpired == "" || rec.LastSeenAt.Before(s.state.Hostnames[bestExpired].LastSeenAt)) {
			bestExpired = hostname
		}
	}
	switch {
	case bestVoteless != "":
		delete(s.state.Hostnames, bestVoteless)
		return true
	case bestExpired != "":
		delete(s.state.Hostnames, bestExpired)
		return true
	default:
		return false
	}
}

// snapshotLocked deep-copies the persisted state for rollback.
func (s *ReputationStore) snapshotLocked() persistedReputation {
	snapshot := persistedReputation{
		VoterSecret: s.state.VoterSecret,
		Voters:      make(map[string]bool, len(s.state.Voters)),
		Hostnames:   make(map[string]*reputationRecord, len(s.state.Hostnames)),
	}
	maps.Copy(snapshot.Voters, s.state.Voters)
	for hostname, rec := range s.state.Hostnames {
		snapshot.Hostnames[hostname] = rec.copy()
	}
	return snapshot
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

func downRatio(total, down int) float64 {
	if total == 0 {
		return 0
	}
	return float64(down) / float64(total)
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

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
	ownerKey, ownerLive := leaseOwner(api.server, hostname)
	summary, minted, err := api.reputation.castVote(hostname, vote, voterCookieID(r), ownerKey, ownerLive)
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
	case errors.Is(err, errReputationVoterBudget),
		errors.Is(err, errReputationHostnameCapacity),
		errors.Is(err, errReputationVoterCapacity):
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
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

// leaseOwner resolves the hostname's current identity key at the vote
// boundary. Absence is not an error: votes outside the live directory still
// count (caps bound them) but carry no owner observation.
func leaseOwner(server *portal.Server, hostname string) (string, bool) {
	for _, lease := range server.PolicyLeases() {
		if normalizeReputationHostname(lease.Hostname) == hostname && lease.IdentityKey != "" {
			return lease.IdentityKey, true
		}
	}
	return "", false
}
