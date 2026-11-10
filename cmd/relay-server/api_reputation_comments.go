package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func commentAuthorHash(r *http.Request) string {
	cookie, err := r.Cookie(commentAuthorCookie)
	if err != nil {
		return ""
	}
	token, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(token) != 32 {
		return ""
	}
	hash := sha256.Sum256(token)
	return hex.EncodeToString(hash[:])
}

func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		utils.WriteAPIError(w, http.StatusUnsupportedMediaType, types.APIErrorCodeInvalidRequest, "application/json is required")
		return false
	}
	return true
}

func (api *RelayAPI) decodeCommentWriteRequest(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if retry := api.reputation.AllowCommentPost(api.ingress.SourceAddr(r)); retry > 0 {
		policy.WriteRetryAfter(w, retry, "Please wait before posting another comment.")
		return "", "", false
	}
	if !requireJSONContentType(w, r) {
		return "", "", false
	}
	req, ok := utils.DecodeJSONRequestAs[types.CreateCommentRequest](w, r, 1<<15, utils.InvalidRequestError(errors.New("invalid comment request")))
	if !ok {
		return "", "", false
	}
	return utils.NormalizeHostname(req.Hostname), req.Text, true
}

func writeCommentErrorResponse(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policy.ErrCommentInvalid):
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, policy.ErrCommentCapacity):
		utils.WriteAPIError(w, http.StatusConflict, types.APIErrorCodeInvalidRequest, "Comment storage is full. Contact the relay administrator.")
	default:
		log.Error().Err(err).Msg("persist comment")
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not save your comment.")
	}
}

func mintCommentAuthor() (string, string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", "", err
	}
	minted := base64.RawURLEncoding.EncodeToString(token)
	hash := sha256.Sum256(token)
	return minted, hex.EncodeToString(hash[:]), nil
}

func (api *RelayAPI) serveComments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var hostname, text string
	switch r.Method {
	case http.MethodGet:
		hostname = utils.NormalizeHostname(r.URL.Query().Get("hostname"))
	case http.MethodPost:
		var ok bool
		hostname, text, ok = api.decodeCommentWriteRequest(w, r)
		if !ok {
			return
		}
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		utils.MethodNotAllowedError().Write(w)
		return
	}
	identity := api.publicIdentityFor(hostname)
	if identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	viewerHash := api.reputation.ViewerHashFor(voterCookieID)
	authorHash := commentAuthorHash(r)

	if r.Method == http.MethodGet {
		utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{Comments: api.reputation.ListComments(identity, viewerHash, authorHash)})
		return
	}
	minted := ""
	if authorHash == "" {
		var err error
		minted, authorHash, err = mintCommentAuthor()
		if err != nil {
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not create comment identity.")
			return
		}
	}
	comments, err := api.reputation.AddComment(identity, text, viewerHash, authorHash)
	if err != nil {
		writeCommentErrorResponse(w, err)
		return
	}
	if minted != "" {
		http.SetCookie(w, &http.Cookie{Name: commentAuthorCookie, Value: minted, Path: types.PathComments, MaxAge: int((10 * 365 * 24 * time.Hour).Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	}
	utils.WriteAPIData(w, http.StatusCreated, types.CommentListResponse{Comments: comments})
}

func (api *RelayAPI) deleteComment(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	req, ok := utils.DecodeJSONRequestAs[types.DeleteCommentRequest](w, r, 1<<12, utils.InvalidRequestError(errors.New("invalid comment deletion request")))
	if !ok {
		return
	}
	identity := api.publicIdentityFor(utils.NormalizeHostname(req.Hostname))
	if identity == "" {
		utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "This app is no longer in the public directory.")
		return
	}
	viewerHash := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		viewerHash = api.reputation.ViewerHashFor(cookie.Value)
	}
	comments, err := api.reputation.DeleteComment(identity, strings.TrimSpace(req.ID), viewerHash, commentAuthorHash(r))
	if err != nil {
		if errors.Is(err, policy.ErrCommentNotFound) {
			utils.WriteAPIError(w, http.StatusNotFound, types.APIErrorCodeInvalidRequest, "Comment not found.")
		} else {
			log.Error().Err(err).Msg("delete comment")
			utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeInternal, "Could not delete this comment.")
		}
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.CommentListResponse{Comments: comments})
}

func (api *RelayAPI) publicIdentityFor(hostname string) string {
	if hostname == "" {
		return ""
	}
	for _, lease := range publicIdentityLeases(api.server.PublicLeases(), api.server) {
		if utils.NormalizeHostname(lease.Hostname) == hostname || utils.NormalizeHostname(lease.CanonicalHostname) == hostname {
			return lease.IdentityKey
		}
	}
	return ""
}
