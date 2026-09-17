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
)

// ReputationConfig is re-exported here for flag wiring in main.go. The
// canonical definition lives in types/reputation.go.
type ReputationConfig = types.ReputationConfig

func defaultReputationConfig() ReputationConfig {
	return types.DefaultReputationConfig()
}

// ReputationMeta is the top-level JSON structure persisted to reputation.json.
// It carries the voter-secret derivation key and the hostname reputation map,
// so that secret rotation preserves voter continuity across relay restarts.
type ReputationMeta struct {
	// VoterSecret is the relay-scoped secret used to derive voter HMACs.
	// It is generated once on first startup and persisted in the state file.
	// Generating it from the relay identity allows restarts without explicit
	// migration while remaining distinct per relay.
	VoterSecret []byte                       `json:"voter_secret,omitempty"`
	Hostnames   map[string]*reputationRecord `json:"hostnames"`
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

// Copy returns a deep copy of the reputation metadata, including all hostname
// records and their voter slices. Used for rollback on persist failure.
func (m ReputationMeta) Copy() ReputationMeta {
	hostnames := make(map[string]*reputationRecord, len(m.Hostnames))
	for k, v := range m.Hostnames {
		if v == nil {
			continue
		}
		hostnames[k] = &reputationRecord{
			UpVoters:        slices.Clone(v.UpVoters),
			DownVoters:      slices.Clone(v.DownVoters),
			OwnerKey:        v.OwnerKey,
			OwnerKeyHistory: slices.Clone(v.OwnerKeyHistory),
			FirstSeenAt:     v.FirstSeenAt,
			LastSeenAt:      v.LastSeenAt,
		}
	}
	return ReputationMeta{
		VoterSecret: slices.Clone(m.VoterSecret),
		Hostnames:   hostnames,
	}
}

type reputationRecord struct {
	UpVoters   []string `json:"up_voters,omitempty"`
	DownVoters []string `json:"down_voters,omitempty"`
	// OwnerKey is the identity key observed at the latest registration.
	OwnerKey string `json:"owner_key,omitempty"`
	// OwnerKeyHistory lists previous owner keys, most recent first, with the
	// moment the key was replaced. A signature-based rotation proof that
	// distinguishes operator rotation from takeover is a follow-up; for now
	// any owner-key difference flags identity_changed_recently.
	OwnerKeyHistory []ownerKeySpan `json:"owner_key_history,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// ownerKeySpan records one replaced owner key and when it was replaced.
type ownerKeySpan struct {
	Key       string    `json:"key"`
	ChangedAt time.Time `json:"changed_at"`
}

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
	if len(store.meta.VoterSecret) == 0 {
		store.meta.VoterSecret = make([]byte, 32)
		if _, err := rand.Read(store.meta.VoterSecret); err != nil {
			return nil, fmt.Errorf("generate reputation voter secret: %w", err)
		}
	}
	store.limiter = policy.NewSourceLimiter(cfg.VoteSourcePerMinute, cfg.VoteSourceBurst, 0, 0)
	store.lastPrune = time.Now().UTC()
	// persistFn intentionally left nil; lazy-initialized on first call so that test
	// injection (which happens after the constructor returns) is not overwritten.
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
// (ObserveLive is the heartbeat that keeps them alive). The state file is
// rewritten only when something actually changed.
func (s *ReputationStore) ObserveLive(live []LiveLease) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false

	// Build the set of live hostnames so they survive retention pruning.
	liveSet := make(map[string]bool, len(live))
	for _, entry := range live {
		hostname := utils.NormalizeHostname(entry.Hostname)
		if hostname == "" {
			continue
		}
		liveSet[hostname] = true
		record := s.meta.Hostnames[hostname]
		if record == nil {
			s.meta.Hostnames[hostname] = &reputationRecord{
				FirstSeenAt: now,
				LastSeenAt:  now,
				OwnerKey:    entry.IdentityKey,
			}
			changed = true
			continue
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
		_ = s.callPersistFn()
	}
}

// allowVote admits one vote for the source address under the store lock, so
// reconfiguration cannot race admission.
func (s *ReputationStore) allowVote(srcIP string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	retry, _ := s.limiter.Allow(srcIP, 1)
	return retry
}

// Knows reports whether the store already carries reputation for hostname.
func (s *ReputationStore) Knows(hostname string) bool {
	hostname = utils.NormalizeHostname(hostname)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.Hostnames[hostname] != nil
}

// ErrReputationBudgetExceeded is returned when a new voter cannot be admitted
// because a per-hostname or relay-wide budget is exhausted.
var ErrReputationBudgetExceeded = errors.New("reputation budget exceeded")

// Vote records voterHash's up/down vote for hostname. Voting the same side
// again is a no-op; the opposite side moves the vote. The state file is
// written before the response, and memory rolls back if the write fails.
func (s *ReputationStore) Vote(hostname, voterHash, vote string) (types.ReputationSummary, error) {
	hostname = utils.NormalizeHostname(hostname)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Snapshot before any mutation so a persist failure fully undoes record
	// creation, eviction, and vote changes alike.
	prevMeta := s.meta.Copy()

	record := s.meta.Hostnames[hostname]
	if record == nil {
		// The caller checked the hostname is (or very recently was) served;
		// a lease that expired in between still gets its fresh record.
		record = &reputationRecord{FirstSeenAt: now, LastSeenAt: now}
		s.meta.Hostnames[hostname] = record
	}

	isNewVoter := !slices.Contains(record.UpVoters, voterHash) && !slices.Contains(record.DownVoters, voterHash)

	if isNewVoter && len(record.UpVoters)+len(record.DownVoters) >= s.cfg.MaxVotersPerHostname {
		return types.ReputationSummary{}, fmt.Errorf("%w: hostname %q has reached the maximum number of voters (%d)", ErrReputationBudgetExceeded, hostname, s.cfg.MaxVotersPerHostname)
	}

	// The new record is already counted above, so evict only when strictly
	// over the relay-wide budget.
	if isNewVoter && len(s.meta.Hostnames) > s.cfg.MaxHostnames {
		oldest := ""
		var oldestTime time.Time
		for h, r := range s.meta.Hostnames {
			if oldest == "" || r.LastSeenAt.Before(oldestTime) {
				oldest, oldestTime = h, r.LastSeenAt
			}
		}
		if oldest != "" {
			delete(s.meta.Hostnames, oldest)
			log.Info().Str("hostname", oldest).Msg("evicted oldest hostname to make room for new voter budget")
		}
	}

	if vote == "up" {
		record.DownVoters = removeReputationVoter(record.DownVoters, voterHash)
		record.UpVoters = upsertReputationVoter(record.UpVoters, voterHash)
	} else {
		record.UpVoters = removeReputationVoter(record.UpVoters, voterHash)
		record.DownVoters = upsertReputationVoter(record.DownVoters, voterHash)
	}

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
func (s *ReputationStore) VoterHash(voterID string) string {
	if voterID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.meta.VoterSecret)
	_, _ = mac.Write([]byte("portal reputation voter v1\n"))
	_, _ = mac.Write([]byte(voterID))
	return hex.EncodeToString(mac.Sum(nil))
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

// reputationVoterIDFromRequest returns the request's well-formed voter cookie
// ID, or "" when absent or malformed. It never issues one.
func reputationVoterIDFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(reputationVoterCookie)
	if err != nil || !validReputationVoterID(cookie.Value) {
		return ""
	}
	return cookie.Value
}

// validReputationVoterID accepts exactly the shape issueReputationVoterID
// mints: base64url of 32 random bytes.
func validReputationVoterID(voterID string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(voterID)
	return err == nil && len(raw) == reputationVoterIDBytes
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

// voterSecret returns the persisted voter secret, used by NewRelayAPI to
// initialize the store. The store generates and persists the secret itself.
func (s *ReputationStore) VoterSecret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.meta.VoterSecret)
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
	voterHash := api.reputation.VoterHash(reputationVoterIDFromRequest(r))
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
	voterID := reputationVoterIDFromRequest(r)
	issued := voterID == ""
	if issued {
		// Cookieless mint: enforce the per-source voter ID budget
		// (in-memory only; resets on relay restart).
		api.cookielessMu.Lock()
		count := len(api.cookielessSources[srcIP])
		limit := api.reputation.Config().MaxVotersPerSource
		if count >= limit {
			api.cookielessMu.Unlock()
			w.Header().Set("Retry-After", "3600")
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited,
				"reputation voter limit exceeded for this source; existing voters can still change their vote")
			return
		}
		// Defer tracking until after we successfully issue and store the voterID.
		defer func() {
			api.cookielessMu.Lock()
			api.cookielessSources[srcIP] = append(api.cookielessSources[srcIP], voterID)
			api.cookielessMu.Unlock()
		}()
		api.cookielessMu.Unlock()

		var err error
		if voterID, err = issueReputationVoterID(); err != nil {
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "could not issue voter identity")
			return
		}
	}

	voterHash := api.reputation.VoterHash(voterID)
	summary, err := api.reputation.Vote(hostname, voterHash, vote)
	if err != nil {
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
			Value:    voterID,
			Path:     types.PathAPIPrefix, // /api — scoped to all /api/* routes
			MaxAge:   int((365 * 24 * time.Hour).Seconds()),
			HttpOnly: true,
			Secure:   strings.HasPrefix(api.server.PortalURL(), "https"),
			SameSite: http.SameSiteLaxMode,
		})
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}
