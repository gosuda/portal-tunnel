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
	// never persisted; only its HMAC under the relay identity secret is stored.
	reputationVoterCookie   = "portal_voter"
	reputationBodyLimit     = 1 << 12
	reputationPruneInterval = time.Hour
	// reputationSeenGranularity quantizes last-seen refreshes so dashboard
	// polling does not rewrite the state file on every request.
	reputationSeenGranularity = 6 * time.Hour
	reputationOwnerHistoryMax = 8
	reputationVoterIDBytes    = 32
)

// ReputationConfig holds the relay-adjustable reputation verdict settings.
type ReputationConfig struct {
	// MinTotal and MinDown floor the vote counts, MinDownRatioPercent the
	// down-vote share, before a hostname is flagged as a service warning.
	MinTotal            int
	MinDown             int
	MinDownRatioPercent int
	// Probation is how long a hostname counts as new and how long an owner-key
	// change stays flagged as identity_changed_recently.
	Probation time.Duration
	// Retention is how long a hostname's reputation survives without appearing
	// in the public lease set.
	Retention time.Duration
	// VoteSourcePerMinute and VoteSourceBurst bound per-source vote admission.
	VoteSourcePerMinute int
	VoteSourceBurst     int
}

func defaultReputationConfig() ReputationConfig {
	return ReputationConfig{
		MinTotal:            5,
		MinDown:             3,
		MinDownRatioPercent: 70,
		Probation:           7 * 24 * time.Hour,
		Retention:           30 * 24 * time.Hour,
		VoteSourcePerMinute: 6,
		VoteSourceBurst:     12,
	}
}

func (c ReputationConfig) validate() error {
	if c.MinTotal < 0 || c.MinDown < 0 {
		return errors.New("reputation vote minimums must be non-negative")
	}
	if c.MinDownRatioPercent < 0 || c.MinDownRatioPercent > 100 {
		return errors.New("reputation down ratio percent must be within 0-100")
	}
	if c.Probation <= 0 || c.Retention <= 0 {
		return errors.New("reputation probation and retention must be positive")
	}
	if c.VoteSourcePerMinute <= 0 || c.VoteSourceBurst <= 0 {
		return errors.New("reputation vote limits must be positive")
	}
	return nil
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
type ReputationStore struct {
	path        string
	cfg         ReputationConfig
	voterSecret []byte
	limiter     *policy.SourceLimiter

	mu        sync.Mutex
	state     reputationState
	lastPrune time.Time
}

type reputationState struct {
	Hostnames map[string]*reputationRecord `json:"hostnames"`
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

func newReputationStore(path string, cfg ReputationConfig, voterSecret []byte) (*ReputationStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("reputation store requires a state path")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if len(voterSecret) == 0 {
		return nil, errors.New("reputation store requires a voter hash secret")
	}
	store := &ReputationStore{path: path, cfg: cfg, voterSecret: voterSecret}
	loaded, err := utils.ReadJSONFileIfExists(path, &store.state)
	if err != nil {
		return nil, fmt.Errorf("load reputation state: %w", err)
	}
	if loaded {
		log.Info().Str("path", path).Int("hostnames", len(store.state.Hostnames)).Msg("restored service reputation")
	}
	if store.state.Hostnames == nil {
		store.state.Hostnames = make(map[string]*reputationRecord)
	}
	store.limiter = policy.NewSourceLimiter(cfg.VoteSourcePerMinute, cfg.VoteSourceBurst, 0, 0)
	store.lastPrune = time.Now().UTC()
	return store, nil
}

// reconfigure swaps operator-adjusted settings before the API serves traffic.
func (s *ReputationStore) reconfigure(cfg ReputationConfig) error {
	if err := cfg.validate(); err != nil {
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
// The state file is rewritten only when something actually changed.
func (s *ReputationStore) ObserveLive(live []LiveLease) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, entry := range live {
		hostname := utils.NormalizeHostname(entry.Hostname)
		if hostname == "" {
			continue
		}
		record := s.state.Hostnames[hostname]
		if record == nil {
			s.state.Hostnames[hostname] = &reputationRecord{
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
		for hostname, record := range s.state.Hostnames {
			if now.Sub(record.LastSeenAt) > s.cfg.Retention {
				delete(s.state.Hostnames, hostname)
				changed = true
			}
		}
	}
	if changed {
		_ = s.persistLocked()
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
	return s.state.Hostnames[hostname] != nil
}

// Vote records voterHash's up/down vote for hostname. Voting the same side
// again is a no-op; the opposite side moves the vote. The state file is
// written before the response, and memory rolls back if the write fails.
func (s *ReputationStore) Vote(hostname, voterHash, vote string) (types.ReputationSummary, error) {
	hostname = utils.NormalizeHostname(hostname)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.state.Hostnames[hostname]
	if record == nil {
		// The caller checked the hostname is (or very recently was) served;
		// a lease that expired in between still gets its fresh record.
		record = &reputationRecord{FirstSeenAt: now, LastSeenAt: now}
		s.state.Hostnames[hostname] = record
	}
	prevUp, prevDown := slices.Clone(record.UpVoters), slices.Clone(record.DownVoters)
	if vote == "up" {
		record.DownVoters = removeReputationVoter(record.DownVoters, voterHash)
		record.UpVoters = upsertReputationVoter(record.UpVoters, voterHash)
	} else {
		record.UpVoters = removeReputationVoter(record.UpVoters, voterHash)
		record.DownVoters = upsertReputationVoter(record.DownVoters, voterHash)
	}
	if err := s.persistLocked(); err != nil {
		record.UpVoters, record.DownVoters = prevUp, prevDown
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
	record := s.state.Hostnames[hostname]
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
// under the relay identity secret. Raw voter IDs and client IPs never reach
// the state file.
func (s *ReputationStore) VoterHash(voterID string) string {
	if voterID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.voterSecret)
	_, _ = mac.Write([]byte("portal reputation voter v1\n"))
	_, _ = mac.Write([]byte(voterID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *ReputationStore) persistLocked() error {
	if err := utils.WriteJSONFile(s.path, s.state, 0o600); err != nil {
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
	if retry := api.reputation.allowVote(api.server.PolicyRuntime().ExtractClientIP(r)); retry > 0 {
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
		var err error
		if voterID, err = issueReputationVoterID(); err != nil {
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "could not issue voter identity")
			return
		}
	}
	summary, err := api.reputation.Vote(hostname, api.reputation.VoterHash(voterID), vote)
	if err != nil {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "reputation vote could not be persisted")
		return
	}
	if issued {
		http.SetCookie(w, &http.Cookie{
			Name:     reputationVoterCookie,
			Value:    voterID,
			Path:     types.PathReputation,
			MaxAge:   int((365 * 24 * time.Hour).Seconds()),
			HttpOnly: true,
			Secure:   strings.HasPrefix(api.server.PortalURL(), "https"),
			SameSite: http.SameSiteLaxMode,
		})
	}
	utils.WriteAPIData(w, http.StatusOK, summary)
}
