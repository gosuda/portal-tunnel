package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// reputationVoterCookie carries the relay-issued voter ID. The ID itself is
	// never persisted; only its HMAC under the relay voter secret is stored.
	reputationVoterCookie   = "portal_voter"
	reputationBodyLimit     = 1 << 12
	reputationPruneInterval = time.Hour
	// reputationSeenGranularity quantizes last-seen refreshes so dashboard
	// polling does not rewrite the state file on every request.
	reputationSeenGranularity = 6 * time.Hour
	reputationOwnerHistoryMax = 8
	reputationVoterIDBytes    = 32
	// reputationReconcileInterval is how often the relay API pulls the current
	// public lease set into the reputation store. First-seen capture and
	// owner-key tracking therefore lag a registration by at most one
	// interval; deliberately not operator-configurable.
	reputationReconcileInterval = time.Minute
)

// ReputationConfig is re-exported here for flag wiring in main.go. The
// canonical definitions of the config and the persisted meta/record structures
// live in types/reputation.go; reputation.go uses those types.
type ReputationConfig = types.ReputationConfig
type ReputationMeta = types.ReputationMeta

func defaultReputationConfig() ReputationConfig {
	return types.DefaultReputationConfig()
}

// LiveLease is one publicly visible lease hostname with its owner identity key.
type LiveLease struct {
	Hostname    string
	IdentityKey string
}

// ReputationStore is the single owner of relay-local service reputation keyed
// by public hostname (never by lease ID, so reputation survives restarts and
// re-registrations). It persists to StateDir/reputation.json beside
// policy.json. Voter identities and client IPs are stored only as HMACs; no
// raw IP ever reaches this file.
//
// The relay-scoped voter-secret is stored in the same file so that voter
// identity remains stable across relay restarts without depending on the
// relay identity token (which rotates with each startup). The secret is
// generated once and never changes unless the file is deleted.
type ReputationStore struct {
	path    string
	cfg     ReputationConfig
	limiter *policy.SourceLimiter

	mu        sync.Mutex
	meta      ReputationMeta
	lastPrune time.Time
	// persistFn writes the current meta to disk. It is a field so tests can
	// replace it with a failing closure to verify rollback behaviour.
	persistFn func() error
}

type reputationRecord = types.ReputationRecord

type ownerKeySpan = types.OwnerKeySpan

func newReputationStore(path string, cfg ReputationConfig) (*ReputationStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("reputation store requires a state path")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	store := &ReputationStore{path: path, cfg: cfg}
	loaded, err := utils.ReadJSONFileIfExists(path, &store.meta)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if loaded {
		log.Info().Str("path", path).Int("hostnames", len(store.meta.Hostnames)).Msg("restored service reputation")
	}
	if store.meta.Hostnames == nil {
		store.meta.Hostnames = make(map[string]*reputationRecord)
	}
	generatedSecret := false
	if len(store.meta.VoterSecret) == 0 {
		store.meta.VoterSecret = make([]byte, 32)
		if _, err := rand.Read(store.meta.VoterSecret); err != nil {
			return nil, fmt.Errorf("generate reputation voter secret: %w", err)
		}
		generatedSecret = true
	}
	store.limiter = policy.NewSourceLimiter(cfg.VoteSourcePerMinute, cfg.VoteSourceBurst, 0, 0)
	store.lastPrune = time.Now().UTC()
	if generatedSecret {
		// Persist the freshly generated secret before returning so that every
		// voter hash derived after startup is restart-stable from the start.
		if err := store.callPersistFn(); err != nil {
			return nil, fmt.Errorf("persist reputation voter secret: %w", err)
		}
	}
	// persistFn intentionally left nil on the loaded path; lazy-initialized on
	// first call so that test injection (which happens after the constructor
	// returns) is not overwritten.
	return store, nil
}

// reconfigure swaps operator-adjusted settings before the API serves traffic.
func (s *ReputationStore) reconfigure(cfg ReputationConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.limiter = policy.NewSourceLimiter(cfg.VoteSourcePerMinute, cfg.VoteSourceBurst, 0, 0)
	return nil
}

// ObserveLive records that these public hostnames are being served now: first
// sight, owner-key comparison for identity changes, and retention pruning.
// Hostnames present in the live set are never pruned by retention expiry
// (ObserveLive is the heartbeat that keeps them alive). Admission honours the
// relay-wide MaxHostnames budget: a full map evicts only voteless records, and
// a map full of voted records skips tracking new hostnames. The state file is
// rewritten only when something actually changed; on persist failure both the
// metadata and the prune clock are restored and the error is returned.
func (s *ReputationStore) ObserveLive(live []LiveLease) error {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Snapshot before any mutation so a persist failure fully undoes record
	// creation, seen refreshes, owner-key moves, and prune-clock advances.
	prevMeta := s.meta.Copy()
	prevPrune := s.lastPrune
	changed := false

	// Build the set of live hostnames so they survive retention pruning.
	liveSet := make(map[string]bool, len(live))
	for _, entry := range live {
		hostname := utils.NormalizeHostname(entry.Hostname)
		if hostname == "" {
			continue
		}
		liveSet[hostname] = true
		record, created := s.admitLocked(hostname, now)
		if record == nil {
			// The relay-wide budget is full of voted records; skip tracking
			// this hostname rather than evicting a voter.
			continue
		}
		if created {
			changed = true
		}
		if now.Sub(record.LastSeenAt) >= reputationSeenGranularity {
			record.LastSeenAt = now
			changed = true
		}
		switch {
		case entry.IdentityKey == "" || record.OwnerKey == entry.IdentityKey:
		case record.OwnerKey == "":
			record.OwnerKey = entry.IdentityKey
			changed = true
		default:
			record.OwnerKeyHistory = append([]ownerKeySpan{{Key: record.OwnerKey, ChangedAt: now}}, record.OwnerKeyHistory...)
			record.OwnerKeyHistory = record.OwnerKeyHistory[:min(len(record.OwnerKeyHistory), reputationOwnerHistoryMax)]
			record.OwnerKey = entry.IdentityKey
			changed = true
		}
	}

	if now.Sub(s.lastPrune) >= reputationPruneInterval {
		s.lastPrune = now
		for hostname, record := range s.meta.Hostnames {
			// Live hostnames survive retention expiry; only dormant ones are pruned.
			if liveSet[hostname] {
				continue
			}
			if now.Sub(record.LastSeenAt) > s.cfg.Retention {
				delete(s.meta.Hostnames, hostname)
				changed = true
			}
		}
	}

	if changed {
		if err := s.callPersistFn(); err != nil {
			s.meta = prevMeta
			s.lastPrune = prevPrune
			return err
		}
	}
	return nil
}

// admitLocked returns the record for hostname, creating a fresh one when
// absent and the relay-wide budget has room. A full map evicts the oldest
// voteless record (no up or down votes) to make room; voted records are never
// evicted. A map that holds only voted records returns (nil, false). The map
// length never exceeds MaxHostnames. created reports whether a new record was
// admitted, so callers can mark the state dirty.
func (s *ReputationStore) admitLocked(hostname string, now time.Time) (*reputationRecord, bool) {
	if record := s.meta.Hostnames[hostname]; record != nil {
		return record, false
	}
	if len(s.meta.Hostnames) < s.cfg.MaxHostnames {
		record := &reputationRecord{FirstSeenAt: now, LastSeenAt: now}
		s.meta.Hostnames[hostname] = record
		return record, true
	}
	oldest := ""
	var oldestTime time.Time
	for h, r := range s.meta.Hostnames {
		if len(r.UpVoters)+len(r.DownVoters) != 0 {
			continue
		}
		if oldest == "" || r.LastSeenAt.Before(oldestTime) {
			oldest, oldestTime = h, r.LastSeenAt
		}
	}
	if oldest == "" {
		return nil, false
	}
	delete(s.meta.Hostnames, oldest)
	log.Info().Str("hostname", oldest).Msg("evicted oldest voteless hostname to admit a new one")
	record := &reputationRecord{FirstSeenAt: now, LastSeenAt: now}
	s.meta.Hostnames[hostname] = record
	return record, true
}

// allowVote admits one vote for the source address under the store lock, so
// reconfiguration cannot race admission.
func (s *ReputationStore) allowVote(srcIP string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	retry, _ := s.limiter.Allow(srcIP, 1)
	return retry
}

// Knows reports whether the store carries unexpired reputation for hostname.
// It is read-only: records past Retention are left in place for ObserveLive's
// prune pass but stop admitting votes.
func (s *ReputationStore) Knows(hostname string) bool {
	hostname = utils.NormalizeHostname(hostname)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.meta.Hostnames[hostname]
	if record == nil {
		return false
	}
	return now.Sub(record.LastSeenAt) <= s.cfg.Retention
}

// ErrReputationBudgetExceeded is returned when a new voter cannot be admitted
// because a per-hostname or relay-wide budget is exhausted.
var ErrReputationBudgetExceeded = errors.New("reputation budget exceeded")

// Vote records voterHash's up/down vote for hostname. Voting the same side
// again is a no-op; the opposite side moves the vote. A vote refreshes the
// record's LastSeenAt (a vote implies directory presence). Admission honours
// the relay-wide MaxHostnames budget by evicting the oldest voteless record;
// voted records are never evicted, so a full map of voted hostnames rejects
// new voters with ErrReputationBudgetExceeded. The state file is written
// before the response, and memory rolls back if the write fails.
func (s *ReputationStore) Vote(hostname, voterHash, vote string) (types.ReputationSummary, error) {
	hostname = utils.NormalizeHostname(hostname)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Snapshot before any mutation so a persist failure fully undoes record
	// creation, eviction, and vote changes alike.
	prevMeta := s.meta.Copy()

	record, _ := s.admitLocked(hostname, now)
	if record == nil {
		return types.ReputationSummary{}, fmt.Errorf("%w: relay-wide budget of %d hostnames is full of voted records", ErrReputationBudgetExceeded, s.cfg.MaxHostnames)
	}

	isNewVoter := !slices.Contains(record.UpVoters, voterHash) && !slices.Contains(record.DownVoters, voterHash)

	if isNewVoter && len(record.UpVoters)+len(record.DownVoters) >= s.cfg.MaxVotersPerHostname {
		return types.ReputationSummary{}, fmt.Errorf("%w: hostname %q has reached the maximum number of voters (%d)", ErrReputationBudgetExceeded, hostname, s.cfg.MaxVotersPerHostname)
	}

	if vote == "up" {
		record.DownVoters = removeReputationVoter(record.DownVoters, voterHash)
		record.UpVoters = upsertReputationVoter(record.UpVoters, voterHash)
	} else {
		record.UpVoters = removeReputationVoter(record.UpVoters, voterHash)
		record.DownVoters = upsertReputationVoter(record.DownVoters, voterHash)
	}
	// A vote implies directory presence: refresh the seen timestamp so the
	// record survives retention while it keeps receiving votes.
	record.LastSeenAt = now

	if err := s.callPersistFn(); err != nil {
		// Restore the full Hostnames map snapshot on persist failure so that new
		// hostname additions and evictions are fully undone.
		s.meta = prevMeta
		return types.ReputationSummary{}, err
	}
	return s.summaryLocked(hostname, voterHash, now), nil
}

// Summary returns the public reputation aggregate for hostname. voterHash
// comes from the request's voter cookie; empty omits the viewer's own vote.
func (s *ReputationStore) Summary(hostname, voterHash string) types.ReputationSummary {
	hostname = utils.NormalizeHostname(hostname)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.summaryLocked(hostname, voterHash, time.Now().UTC())
}

func (s *ReputationStore) summaryLocked(hostname, voterHash string, now time.Time) types.ReputationSummary {
	summary := types.ReputationSummary{}
	record := s.meta.Hostnames[hostname]
	if record == nil {
		return summary
	}
	summary.Up = len(record.UpVoters)
	summary.Down = len(record.DownVoters)
	summary.Total = summary.Up + summary.Down
	if summary.Total > 0 {
		summary.DownRatio = float64(summary.Down) / float64(summary.Total)
	}
	summary.Warning = summary.Total >= s.cfg.MinTotal &&
		summary.Down >= s.cfg.MinDown &&
		summary.DownRatio >= float64(s.cfg.MinDownRatioPercent)/100
	summary.IsNew = now.Sub(record.FirstSeenAt) < s.cfg.Probation
	summary.IdentityChangedRecently = len(record.OwnerKeyHistory) > 0 &&
		now.Sub(record.OwnerKeyHistory[0].ChangedAt) < s.cfg.Probation
	summary.FirstSeenAt = record.FirstSeenAt
	switch {
	case voterHash == "":
	case slices.Contains(record.UpVoters, voterHash):
		summary.ViewerVote = "up"
	case slices.Contains(record.DownVoters, voterHash):
		summary.ViewerVote = "down"
	}
	return summary
}

// VoterHash keys the stored voter identity: HMAC over the voter cookie ID
// under the relay-scoped voter secret (stored in reputation.json, not derived
// from the relay identity). Raw voter IDs and client IPs never reach the file.
// The secret is copied under the store lock; hashing runs outside it.
func (s *ReputationStore) VoterHash(voterID string) string {
	if voterID == "" {
		return ""
	}
	secret := s.voterSecret()
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("portal reputation voter v1\n"))
	_, _ = mac.Write([]byte(voterID))
	return hex.EncodeToString(mac.Sum(nil))
}

// signReputationVoterID wraps a voter ID into the self-authenticating cookie
// value base64url(id) + "." + base64url(HMAC_SHA256(voterSecret, id)). The
// minted ID can only be replayed, not manufactured: a cookie whose MAC does
// not verify is treated as cookieless and counted against the mint budget.
func (s *ReputationStore) signReputationVoterID(voterID string) string {
	mac := hmac.New(sha256.New, s.voterSecret())
	_, _ = mac.Write([]byte(voterID))
	return voterID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// voterIDFromCookie verifies a signed voter cookie and returns the voter ID
// part. Any malformed value, wrong length, or invalid MAC reports false.
func (s *ReputationStore) voterIDFromCookie(value string) (string, bool) {
	idPart, macPart, ok := strings.Cut(value, ".")
	if !ok {
		return "", false
	}
	id, err := base64.RawURLEncoding.DecodeString(idPart)
	if err != nil || len(id) != reputationVoterIDBytes {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil || len(got) != sha256.Size {
		return "", false
	}
	mac := hmac.New(sha256.New, s.voterSecret())
	_, _ = mac.Write([]byte(idPart))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return "", false
	}
	return idPart, true
}

// voterSecret returns a copy of the persisted voter secret so callers can
// hash without holding the store lock.
func (s *ReputationStore) voterSecret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.meta.VoterSecret)
}

// callPersistFn lazily initializes persistFn on first use so that test injection
// (which happens after the constructor returns) is not overwritten.
func (s *ReputationStore) callPersistFn() error {
	if s.persistFn == nil {
		s.persistFn = s.persistLockedImpl
	}
	return s.persistFn()
}

func (s *ReputationStore) persistLockedImpl() error {
	if err := utils.WriteJSONFile(s.path, s.meta, 0o600); err != nil {
		log.Error().Err(err).Str("path", s.path).Msg("persist service reputation")
		return err
	}
	return nil
}

func upsertReputationVoter(voters []string, voterHash string) []string {
	if slices.Contains(voters, voterHash) {
		return voters
	}
	return append(voters, voterHash)
}

func removeReputationVoter(voters []string, voterHash string) []string {
	return slices.DeleteFunc(slices.Clone(voters), func(candidate string) bool {
		return candidate == voterHash
	})
}

// reputationVoterIDFromRequest returns the request's signature-verified voter
// ID, or "" when the cookie is absent, malformed, or forged. It never issues
// one: an unverified cookie takes the cookieless mint path.
func reputationVoterIDFromRequest(store *ReputationStore, r *http.Request) string {
	cookie, err := r.Cookie(reputationVoterCookie)
	if err != nil {
		return ""
	}
	id, ok := store.voterIDFromCookie(cookie.Value)
	if !ok {
		return ""
	}
	return id
}

func issueReputationVoterID() (string, error) {
	var raw [reputationVoterIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate reputation voter id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// validReputationHostname accepts lowercase DNS hostnames: dotted labels of
// alphanumerics and inner hyphens, at most 253 characters overall.
func validReputationHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			lower := c >= 'a' && c <= 'z'
			digit := c >= '0' && c <= '9'
			if !lower && !digit && c != '-' {
				return false
			}
		}
	}
	return true
}

// Config returns a copy of the current runtime configuration.
func (s *ReputationStore) Config() ReputationConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// applyReputationConfig swaps the operator-adjusted reputation settings into
// the store before the API serves traffic.
func (api *RelayAPI) applyReputationConfig(cfg ReputationConfig) error {
	return api.reputation.reconfigure(cfg)
}

func (api *RelayAPI) serveReputation(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	hostname := utils.NormalizeHostname(r.URL.Query().Get("hostname"))
	if !validReputationHostname(hostname) {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid hostname")
		return
	}
	voterHash := api.reputation.VoterHash(reputationVoterIDFromRequest(api.reputation, r))
	utils.WriteAPIData(w, http.StatusOK, api.reputation.Summary(hostname, voterHash))
}

func (api *RelayAPI) serveReputationVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.ReputationVoteRequest](w, r, reputationBodyLimit, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	hostname := utils.NormalizeHostname(req.Hostname)
	if !validReputationHostname(hostname) {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid hostname")
		return
	}
	vote := strings.ToLower(strings.TrimSpace(req.Vote))
	if vote != "up" && vote != "down" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, `vote must be "up" or "down"`)
		return
	}
	srcIP := api.server.PolicyRuntime().ExtractClientIP(r)
	if retry := api.reputation.allowVote(srcIP); retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "reputation vote rate exceeded")
		return
	}
	// Only hostnames the relay serves now or served before accept votes, so
	// unclaimed names cannot be pre-polluted ahead of a registration.
	live := false
	for _, lease := range api.server.PublicLeases() {
		if utils.NormalizeHostname(lease.Hostname) == hostname {
			live = true
			break
		}
	}
	if !live && !api.reputation.Knows(hostname) {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeNotFound, "hostname is not served by this relay")
		return
	}
	voterID := reputationVoterIDFromRequest(api.reputation, r)
	issued := voterID == ""
	if issued {
		// Cookieless mint: budget checks, ID generation, and the tracking
		// append all happen inside one critical section, and the reservation
		// is rolled back if the vote itself fails. Generation is pure
		// rand.Read, so no I/O happens under the lock.
		api.cookielessMu.Lock()
		cfg := api.reputation.Config()
		if _, known := api.cookielessSources[srcIP]; !known && len(api.cookielessSources) >= cfg.MaxMintSources {
			// Fail closed for new sources only: existing sources keep their
			// own budgets untouched.
			api.cookielessMu.Unlock()
			w.Header().Set("Retry-After", "3600")
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited,
				"reputation mint source limit exceeded")
			return
		}
		if len(api.cookielessSources[srcIP]) >= cfg.MaxVotersPerSource {
			api.cookielessMu.Unlock()
			w.Header().Set("Retry-After", "3600")
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited,
				"reputation voter limit exceeded for this source; existing voters can still change their vote")
			return
		}
		generated, err := issueReputationVoterID()
		if err != nil {
			api.cookielessMu.Unlock()
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "could not issue voter identity")
			return
		}
		// Only successfully generated IDs are appended; "" is never tracked.
		api.cookielessSources[srcIP] = append(api.cookielessSources[srcIP], generated)
		api.cookielessMu.Unlock()
		voterID = generated
	}

	voterHash := api.reputation.VoterHash(voterID)
	summary, err := api.reputation.Vote(hostname, voterHash, vote)
	if err != nil {
		if issued {
			// Roll back the reservation so a failed vote does not consume the
			// mint budget.
			api.cookielessMu.Lock()
			api.cookielessSources[srcIP] = slices.DeleteFunc(api.cookielessSources[srcIP], func(tracked string) bool {
				return tracked == voterID
			})
			if len(api.cookielessSources[srcIP]) == 0 {
				delete(api.cookielessSources, srcIP)
			}
			api.cookielessMu.Unlock()
		}
		if errors.Is(err, ErrReputationBudgetExceeded) || strings.Contains(err.Error(), "rate limited") {
			w.Header().Set("Retry-After", "3600")
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, err.Error())
			return
		}
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "reputation vote could not be persisted")
		return
	}

	if issued {
		http.SetCookie(w, &http.Cookie{
			Name:     reputationVoterCookie,
			Value:    api.reputation.signReputationVoterID(voterID),
			Path:     types.PathAPIPrefix, // /api — scoped to all /api/* routes
			MaxAge:   int((365 * 24 * time.Hour).Seconds()),
			HttpOnly: true,
			Secure:   strings.HasPrefix(api.server.PortalURL(), "https"),
			SameSite: http.SameSiteLaxMode,
		})
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}
