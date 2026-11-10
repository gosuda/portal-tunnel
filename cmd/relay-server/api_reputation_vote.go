package main

import (
	"cmp"
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

func requestVoterCookieID(r *http.Request) string {
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		return cookie.Value
	}
	return ""
}

func (api *RelayAPI) serveVote(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	commentVote := r.URL.Path == types.PathCommentsVote
	sourceAddr := api.ingress.SourceAddr(r)
	if retry := api.reputation.AllowVote(sourceAddr, commentVote); retry > 0 {
		policy.WriteRetryAfter(w, retry, "vote request budget exhausted")
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.VoteRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid request body")))
	if !ok {
		return
	}
	if commentVote {
		req.ID = strings.TrimSpace(req.ID)
		if req.ID == "" {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "comment id is required")
			return
		}
	} else {
		req.ID = ""
	}
	hostname := utils.NormalizeHostname(req.Hostname)
	if !commentVote && hostname == "" {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "hostname is required")
		return
	}
	identity := api.publicIdentityFor(hostname)
	if commentVote && identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	voterCookieID := requestVoterCookieID(r)
	summary, minted, err := api.reputation.Vote(identity, req.ID, req.Vote, voterCookieID, sourceAddr)
	if err != nil {
		writeVoteErrorResponse(w, err)
		return
	}
	setVoterCookie(w, r, minted)
	if commentVote {
		viewerHash := api.reputation.ViewerHashFor(cmp.Or(minted, voterCookieID))
		utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{
			Comments: api.reputation.ListComments(identity, viewerHash, commentAuthorHash(r)),
		})
	} else {
		utils.WriteAPIData(w, http.StatusOK, policy.ReputationSummary{
			Hostname:    hostname,
			Comments:    api.reputation.CommentsCount(identity),
			VoteSummary: summary,
		})
	}
}
func writeVoteErrorResponse(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policy.ErrVoteChoice):
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, policy.ErrReputationCapacity):
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "vote capacity reached")
	case errors.Is(err, policy.ErrReputationUnknownHostname):
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "hostname is not in the public directory")
	case errors.Is(err, policy.ErrCommentNotFound):
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "comment not found")
	case errors.Is(err, policy.ErrCommentCapacity):
		utils.WriteAPIError(w, http.StatusConflict, types.APIErrorCodeInvalidRequest, "comment vote storage limit reached")
	default:
		log.Error().Err(err).Msg("persist vote")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "could not save vote")
	}
}

func setVoterCookie(w http.ResponseWriter, r *http.Request, minted string) {
	if minted == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     reputationVoterCookie,
		Value:    minted,
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
		known[utils.NormalizeHostname(lease.CanonicalHostname)] = true
	}
	leases := make([]types.PolicyLease, 0)
	for _, lease := range server.PolicyLeases() {
		if known[utils.NormalizeHostname(lease.CanonicalHostname)] && lease.IdentityKey != "" {
			leases = append(leases, lease)
		}
	}
	return leases
}
