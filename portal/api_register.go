package portal

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) (types.ServiceIdentityKey, types.RegisterResponse, bool) {
	req, ok := utils.DecodeJSONRequest[types.RegisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return types.ServiceIdentityKey{}, types.RegisterResponse{}, false
	}

	challenge, sourceAddr, err := s.registry.consumeVerifiedRegisterChallenge(req)
	if err != nil {
		s.writeHandleRegisterChallengeError(w, err)
		return types.ServiceIdentityKey{}, types.RegisterResponse{}, false
	}
	identityKey := challenge.Request.Identity.ServiceKey()
	// A registering identity starts fail-closed. Mux replaces this projection
	// with the relay's current access decision before publishing success.
	s.registry.suspendIdentity(identityKey)

	self, descriptors := s.issueHandleRegisterDescriptors(challenge)
	record, replaced, resp, err := s.registry.Register(challenge.Request, sourceAddr, req.ReportedIP, self, descriptors, s.acmeManager.TLSMaterial())
	if replaced != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
		s.deleteLeaseDNS(cleanupCtx, replaced)
		cleanupCancel()
	}
	if err != nil {
		writeAPIErrorResponse(w, err)
		return identityKey, types.RegisterResponse{}, false
	}
	if !s.syncHandleRegisterLeaseDNS(w, r, record, resp) {
		return identityKey, types.RegisterResponse{}, false
	}
	if record.tcpPort > 0 {
		go s.serveTCP(record)
	}

	return record.ServiceKey(), resp, true
}

func (s *Server) writeHandleRegisterChallengeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrRegisterChallengeInvalidSignature):
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, err.Error())
	default:
		utils.InvalidRequestError(err).Write(w)
	}
}

func (s *Server) issueHandleRegisterDescriptors(challenge *identity.RegisterChallenge) (types.RelayDescriptor, []types.RelayDescriptor) {
	if !challenge.Request.Overlay {
		return types.RelayDescriptor{}, nil
	}
	self, descriptors, err := s.overlayIssueDescriptors(time.Now().UTC())
	if err != nil {
		log.Warn().Err(err).Str("lease", challenge.Request.Identity.Key()).Msg("relay overlay descriptors unavailable; using direct reverse transport")
		return types.RelayDescriptor{}, nil
	}
	return self, descriptors
}

func (s *Server) syncHandleRegisterLeaseDNS(w http.ResponseWriter, r *http.Request, record *leaseRecord, resp types.RegisterResponse) bool {
	dnsCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
	err := s.syncLeaseDNS(dnsCtx, record)
	cancel()
	if err != nil {
		removed, _ := s.registry.Unregister(types.UnregisterRequest{AccessToken: resp.AccessToken})
		if removed == nil {
			s.registry.closeRecord(record)
			removed = record
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
		s.deleteLeaseDNS(cleanupCtx, removed)
		cleanupCancel()
		writeAPIErrorResponse(w, err)
		return false
	}
	return true
}

// HandleRegisterChallenge issues a registration challenge without publishing
// the success response, allowing the relay to apply access state first.
func (s *Server) HandleRegisterChallenge(w http.ResponseWriter, r *http.Request, sourceAddr netip.Addr) (types.ServiceIdentityKey, types.RegisterChallengeResponse, bool) {
	req, ok := utils.DecodeJSONRequest[types.RegisterChallengeRequest](w, r, 64<<10)
	if !ok {
		return types.ServiceIdentityKey{}, types.RegisterChallengeResponse{}, false
	}

	return s.createChallengeResponse(w, r, req, sourceAddr)
}

func (s *Server) createChallengeResponse(w http.ResponseWriter, r *http.Request, req types.RegisterChallengeRequest, sourceAddr netip.Addr) (types.ServiceIdentityKey, types.RegisterChallengeResponse, bool) {
	domain, registerURI := s.buildHandleRegisterChallengeURI(r)
	if s.rejectDisabledTransports(w, req) {
		return types.ServiceIdentityKey{}, types.RegisterChallengeResponse{}, false
	}
	normalized, err := identity.NormalizeIdentity(req.Identity)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return types.ServiceIdentityKey{}, types.RegisterChallengeResponse{}, false
	}
	req.Identity = normalized
	identityKey := normalized.ServiceKey()
	resp, err := s.registry.issueRegisterChallenge(req, domain, registerURI, sourceAddr)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return identityKey, types.RegisterChallengeResponse{}, false
	}
	return identityKey, resp, true
}

func (s *Server) buildHandleRegisterChallengeURI(r *http.Request) (string, string) {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	domain := strings.TrimSpace(r.Host)
	domain = cmp.Or(domain, s.identity.Name)
	registerURI := (&url.URL{
		Scheme: scheme,
		Host:   domain,
		Path:   types.PathSDKRegister,
	}).String()
	return domain, registerURI
}

func (s *Server) rejectDisabledTransports(w http.ResponseWriter, req types.RegisterChallengeRequest) bool {
	if req.UDPEnabled && !s.supportsUDP() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUDPDisabled,
			"UDP transport is disabled on this relay")
		return true
	}
	if req.TCPEnabled && !s.supportsTCP() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeTCPPortDisabled,
			"raw TCP transport is disabled on this relay")
		return true
	}
	return false
}

// RefuseChallengeOverBudget reports whether it answered 429 because the source
// of the challenge just issued for key is over its unapproved lease budget. Call
// it after applying the identity's access decision: only then does the registry
// know that a new identity is unapproved.
func (s *Server) RefuseChallengeOverBudget(w http.ResponseWriter, key types.ServiceIdentityKey, challengeID string, sourceAddr netip.Addr) bool {
	err := s.registry.refuseChallengeOverBudget(key, challengeID, sourceAddr)
	if err == nil {
		return false
	}
	w.Header().Set("Retry-After", unapprovedLeaseRetryAfter)
	writeAPIErrorResponse(w, err)
	return true
}

func (s *Server) HandleRenew(w http.ResponseWriter, r *http.Request, sourceAddr netip.Addr) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.RenewRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}

	resp, endpointInput, err := s.registry.Renew(req, sourceAddr, s.acmeManager.TLSMaterial())
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	resp.ReverseEndpoint, err = s.issueReverseEndpoint(endpointInput)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}

	utils.WriteAPIData(w, http.StatusOK, resp)
}

func (s *Server) HandleUnregister(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}

	req, ok := utils.DecodeJSONRequest[types.UnregisterRequest](w, r, defaultControlBodyLimit)
	if !ok {
		return
	}
	record, err := s.registry.Unregister(req)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	dnsCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), defaultClaimTimeout)
	s.deleteLeaseDNS(dnsCtx, record)
	cancel()

	utils.WriteAPIData(w, http.StatusOK, map[string]any{})
}
