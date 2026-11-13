package portal

import (
	"bytes"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (r *leaseRegistry) admitLeaseByToken(token string, requireDatagram bool) (*leaseRecord, error) {
	if r == nil {
		return nil, errFeatureUnavailable
	}
	now := time.Now().UTC()
	claims, err := identity.VerifyLeaseAccessToken(token, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return nil, errUnauthorized
	}
	return r.admitLeaseIdentity(claims.Identity.ServiceKey(), claims.LeaseID, now, requireDatagram)
}

func (r *leaseRegistry) admitReverseCapability(token string) (*leaseRecord, error) {
	if r == nil {
		return nil, errFeatureUnavailable
	}
	now := time.Now().UTC()
	claims, err := identity.VerifyReverseCapability(token, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return nil, errUnauthorized
	}
	return r.admitLeaseIdentity(claims.Identity.ServiceKey(), claims.LeaseID, now, false)
}

func (r *leaseRegistry) admitLeaseIdentity(key types.ServiceIdentityKey, leaseID string, now time.Time, requireDatagram bool) (*leaseRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, err := r.recordForVerifiedLeaseLocked(key, leaseID, now)
	if err != nil {
		return nil, err
	}
	if blocked, ok := r.blocked[record.ServiceKey()]; ok {
		return nil, blocked.refusal
	}
	if record.reverse == nil || (requireDatagram && record.datagram == nil) {
		return nil, errTransportMismatch
	}
	return record, nil
}

type reverseEndpointInput struct {
	leaseIdentity types.Identity
	leaseID       string
	expiresAt     time.Time
	failedURL     string
	useOverlay    bool
}

func (r *leaseRegistry) verifyRenewClaim(req types.RenewRequest) (identity.LeaseAccessTokenClaims, time.Duration, types.ServiceIdentityKey, error) {
	claims, err := identity.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return identity.LeaseAccessTokenClaims{}, 0, types.ServiceIdentityKey{}, errUnauthorized
	}
	if err := req.Metadata.Validate(); err != nil {
		return identity.LeaseAccessTokenClaims{}, 0, types.ServiceIdentityKey{}, err
	}
	ttl, err := requestedLeaseTTL(req.TTL)
	if err != nil {
		return identity.LeaseAccessTokenClaims{}, 0, types.ServiceIdentityKey{}, err
	}
	return claims, ttl, claims.Identity.ServiceKey(), nil
}

func (r *leaseRegistry) refreshRenewRecordLocked(record *leaseRecord, req types.RenewRequest, ttl time.Duration, sourceAddr netip.Addr) (types.Identity, string, bool, time.Time) {
	now := time.Now()
	expiresAt := now.Add(ttl).UTC().Truncate(time.Second)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if sourceAddr.IsValid() {
		record.sourceAddr = sourceAddr
	}
	if reportedIP := utils.SanitizeReportedIP(req.ReportedIP); strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	record.Metadata = req.Metadata.Copy()
	if record.Namespace == types.LocalTLSNamespaceV1 {
		record.localTLSNotAfter = req.LocalTLSNotAfter
	}
	r.cache.Renew(record.cacheLeaseLocked())
	return record.Identity, record.id, record.Overlay, expiresAt
}

func (r *leaseRegistry) Renew(req types.RenewRequest, sourceAddr netip.Addr, current *acme.TLSMaterial) (types.RenewResponse, reverseEndpointInput, error) {
	if r == nil {
		return types.RenewResponse{}, reverseEndpointInput{}, errFeatureUnavailable
	}
	claims, ttl, leaseKey, err := r.verifyRenewClaim(req)
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, err
	}
	r.mu.Lock()
	record, err := r.recordForVerifiedLeaseLocked(leaseKey, claims.LeaseID, time.Time{})
	if err != nil {
		r.mu.Unlock()
		return types.RenewResponse{}, reverseEndpointInput{}, err
	}
	if !req.RepinsChain && r.stalePinLocked(record, current) {
		r.mu.Unlock()
		return types.RenewResponse{}, reverseEndpointInput{}, errLeaseNotFound
	}
	recordIdentity, leaseID, useOverlay, expiresAt := r.refreshRenewRecordLocked(record, req, ttl, sourceAddr)
	r.mu.Unlock()

	nextAccessToken, _, err := identity.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, recordIdentity, leaseID, ttl)
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, &apiError{types.APIErrorCodeInternal, err.Error(), http.StatusInternalServerError}
	}
	return types.RenewResponse{
			ExpiresAt:   expiresAt,
			AccessToken: nextAccessToken,
		}, reverseEndpointInput{
			leaseIdentity: recordIdentity,
			leaseID:       leaseID,
			expiresAt:     expiresAt,
			useOverlay:    useOverlay,
		}, nil
}

func (r *leaseRegistry) stalePinLocked(record *leaseRecord, current *acme.TLSMaterial) bool {
	if record.pinnedChain == nil || current == nil || bytes.Equal(record.pinnedChain, current.CertPEM) || bytes.Equal(record.verifiedChain, current.CertPEM) {
		return false
	}
	if !current.TrustedBy(record.pinnedChain, r.rootHostname) {
		return true
	}
	record.verifiedChain = current.CertPEM
	return false
}

func (r *leaseRegistry) tryRenewOverlayEndpoint(input reverseEndpointInput, self types.RelayDescriptor, descriptors []types.RelayDescriptor) types.ReverseEndpoint {
	var endpoint types.ReverseEndpoint
	if input.useOverlay && r.overlay != nil && self.Address != "" {
		overlayEndpoint, ok, err := r.overlay.IssueEndpoint(overlay.IssueInput{
			LeaseIdentity: input.leaseIdentity,
			LeaseID:       input.leaseID,
			ExpiresAt:     input.expiresAt,
			FailedURL:     input.failedURL,
			Self:          self,
			Descriptors:   descriptors,
		})
		if err == nil && ok {
			endpoint = overlayEndpoint
		}
		if err != nil {
			log.Warn().Err(err).Str("lease", input.leaseIdentity.Key()).Msg("relay overlay endpoint unavailable; using direct reverse transport")
		}
	}
	return endpoint
}

func (r *leaseRegistry) issueReverseEndpoint(input reverseEndpointInput, self types.RelayDescriptor, descriptors []types.RelayDescriptor) (types.ReverseEndpoint, error) {
	endpoint := r.tryRenewOverlayEndpoint(input, self, descriptors)
	if endpoint.URL == "" {
		capability, claims, err := identity.IssueReverseCapability(r.tokenAuthority, r.tokenIssuer, input.leaseIdentity, input.leaseID, input.expiresAt)
		if err != nil {
			return types.ReverseEndpoint{}, err
		}
		endpoint = types.ReverseEndpoint{
			URL:        r.reverseURL,
			Capability: capability,
			ExpiresAt:  claims.Expiry.Time().UTC(),
		}
	}
	r.mu.RLock()
	_, activeErr := r.recordForVerifiedLeaseLocked(input.leaseIdentity.ServiceKey(), input.leaseID, time.Now().UTC())
	r.mu.RUnlock()
	if activeErr != nil {
		if r.overlay != nil {
			r.overlay.ForgetLease(input.leaseID)
		}
		return types.ReverseEndpoint{}, activeErr
	}
	return endpoint, nil
}

func (r *leaseRegistry) resolveReverseEndpoint(req types.ReverseEndpointRequest) (reverseEndpointInput, error) {
	if r == nil {
		return reverseEndpointInput{}, errFeatureUnavailable
	}
	now := time.Now().UTC()
	claims, err := identity.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return reverseEndpointInput{}, errUnauthorized
	}
	r.mu.RLock()
	record, err := r.recordForVerifiedLeaseLocked(claims.Identity.ServiceKey(), claims.LeaseID, now)
	if err != nil {
		r.mu.RUnlock()
		return reverseEndpointInput{}, err
	}
	leaseIdentity := record.Identity
	leaseID := record.id
	expiresAt := record.ExpiresAt
	useOverlay := record.Overlay
	r.mu.RUnlock()
	return reverseEndpointInput{
		leaseIdentity: leaseIdentity,
		leaseID:       leaseID,
		expiresAt:     expiresAt,
		failedURL:     strings.TrimSpace(req.FailedURL),
		useOverlay:    useOverlay,
	}, nil
}

func (r *leaseRegistry) Unregister(req types.UnregisterRequest) (*leaseRecord, error) {
	if r == nil {
		return nil, errFeatureUnavailable
	}
	claims, err := identity.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return nil, errUnauthorized
	}
	r.mu.Lock()

	key := claims.Identity.ServiceKey()
	record := r.recordByLease(key, claims.LeaseID, time.Time{})
	if record == nil {
		r.mu.Unlock()
		return nil, errUnauthorized
	}
	for i, current := range r.records {
		if current != record {
			continue
		}
		r.deleteRecord(i)
		r.bps.ResetIdentityLimiter(key)
		r.mu.Unlock()
		r.closeRecord(record)
		return record, nil
	}
	r.mu.Unlock()
	return nil, errLeaseNotFound
}
