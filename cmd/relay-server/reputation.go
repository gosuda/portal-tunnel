package main

// Service reputation vote wiring: relay-local HTTP glue over the policy
// package's vote ledger. The relay's lease registry owns service lifecycle;
// this file maps a current public hostname to its stable identity and handles
// the voter cookie. portal.Server and shared lease types stay unchanged.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// Relay-local wire paths. Deliberately not in types/paths.go: no Go
	// package outside cmd/relay-server needs them.
	pathReputationVote = types.PathAPIPrefix + "/reputation/vote"

	reputationFilename = "reputation.json"

	reputationVoterCookie = "portal_voter"
)

// Wire contracts. Local to the relay on purpose; the frontend mirrors them.
type reputationVoteRequest struct {
	Hostname string `json:"hostname"`
	Vote     string `json:"vote"`
}

// serveReputationVote is admission -> decode -> store op. Admission runs
// before decoding, matching the pre-auth routes: rate-limited sources pay
// no parse cost, and the body bound applies inside decode.
func (api *RelayAPI) serveReputationVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	clientIP := api.ingress.ClientIP(r)
	if retry := api.reputation.AllowVote(clientIP); retry > 0 {
		policy.WriteRetryAfter(w, retry, "vote request budget exhausted")
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
	if vote != policy.VoteUp && vote != policy.VoteDown {
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
	summary, minted, err := api.reputation.CastVote(hostname, identity, vote, voterCookieID(r), clientIP)
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
	case errors.Is(err, policy.ErrReputationCapacity):
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
	case errors.Is(err, policy.ErrReputationUnknownHostname):
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
