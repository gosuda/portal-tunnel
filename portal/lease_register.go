package portal

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (r *leaseRegistry) enforceRefuseChallengeBudgetLocked(held int, issued int) error {
	if held < r.unapprovedPerSource {
		return nil
	}
	if issued >= 0 {
		r.deleteRecord(issued)
	}
	return errUnapprovedLeaseLimit
}

func (r *leaseRegistry) refuseChallengeOverBudget(key types.ServiceIdentityKey, challengeID string, source netip.Addr) error {
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.unapprovedPerSource <= 0 || !source.IsValid() || r.isRoutableLocked(key) {
		return nil
	}
	held := make(map[types.ServiceIdentityKey]struct{})
	issued := -1
	for i, record := range r.records {
		if record == nil || record.isExpired(now) {
			continue
		}
		var holder types.ServiceIdentityKey
		var isIssued bool
		switch {
		case record.registerChallenge != nil && record.sourceAddr == source:
			holder = record.registerChallenge.Request.Identity.ServiceKey()
			isIssued = record.registerChallenge.ChallengeID == challengeID
		case record.reverse != nil && record.registerSource == source:
			holder = record.ServiceKey()
		default:
			continue
		}
		if isIssued {
			issued = i
		}
		if holder != key && !r.isRoutableLocked(holder) {
			held[holder] = struct{}{}
		}
	}
	return r.enforceRefuseChallengeBudgetLocked(len(held), issued)
}

func (r *leaseRegistry) resolveRegisterHostnames(leaseIdentity types.Identity, canonicalOnly bool) (string, string, error) {
	var publicHostname string
	if leaseIdentity.Name != "" && !canonicalOnly {
		var err error
		publicHostname, err = utils.LeaseHostname(leaseIdentity.Name, r.rootHostname)
		if err != nil {
			return "", "", err
		}
	}
	canonicalHostname, err := utils.CanonicalLeaseHostname(leaseIdentity.Name, leaseIdentity.Address, r.rootHostname)
	if err != nil {
		return "", "", err
	}
	return publicHostname, canonicalHostname, nil
}

func clampRegisterStartedAt(requested time.Time, issuedAt time.Time) time.Time {
	if requested.IsZero() || !requested.Before(issuedAt) {
		return issuedAt
	}
	firstSeenAt := requested.UTC()
	if floor := issuedAt.Add(-maxClaimedStartedAge); firstSeenAt.Before(floor) {
		firstSeenAt = floor
	}
	return firstSeenAt
}

func formatRegisterResponse(record *leaseRecord, accessToken string, reverseEndpoint types.ReverseEndpoint) types.RegisterResponse {
	resp := types.RegisterResponse{
		Identity:          record.Identity,
		Hostname:          record.Hostname,
		CanonicalHostname: record.CanonicalHostname,
		ExpiresAt:         record.ExpiresAt,
		AccessToken:       accessToken,
		ReverseEndpoint:   reverseEndpoint,
		UDPEnabled:        record.datagram != nil,
		TCPEnabled:        record.tcpPort > 0,
	}
	if record.datagram != nil {
		resp.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.tcpPort > 0 {
		resp.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort)
	}
	return resp
}

func (r *leaseRegistry) buildRegisterRecord(req types.RegisterChallengeRequest, sourceAddr netip.Addr, reportedIP string, served *acme.TLSMaterial) (*leaseRecord, string, error) {
	leaseIdentity := req.Identity
	if err := req.Metadata.Validate(); err != nil {
		return nil, "", err
	}
	ttl, err := requestedLeaseTTL(req.TTL)
	if err != nil {
		return nil, "", err
	}
	publicHostname, canonicalHostname, err := r.resolveRegisterHostnames(leaseIdentity, req.CanonicalOnly)
	if err != nil {
		return nil, "", err
	}
	udpEnabled, _ := r.udpPolicy()
	tcpPortEnabled, _ := r.tcpPortPolicy()
	if req.UDPEnabled && !udpEnabled {
		return nil, "", errUDPDisabled
	}
	if req.TCPEnabled && !tcpPortEnabled {
		return nil, "", errTCPPortDisabled
	}
	leaseID := utils.RandomID("lease_")
	accessToken, claims, err := identity.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, leaseIdentity, leaseID, ttl)
	if err != nil {
		return nil, "", err
	}
	expiresAt := claims.Expiry.Time().UTC()
	issuedAt := claims.IssuedAt.Time().UTC()
	record := &leaseRecord{
		Identity:          leaseIdentity,
		id:                leaseID,
		Hostname:          publicHostname,
		CanonicalHostname: canonicalHostname,
		Metadata:          req.Metadata.Copy(),
		Overlay:           req.Overlay,
		ExpiresAt:         expiresAt,
		FirstSeenAt:       clampRegisterStartedAt(req.StartedAt, issuedAt),
		LastSeenAt:        issuedAt,
		sourceAddr:        sourceAddr,
		registerSource:    sourceAddr,
		ReportedIP:        utils.SanitizeReportedIP(reportedIP),
		reverse:           transport.NewReversePool(defaultIdleKeepalive, defaultReadyQueueLimit),
	}
	if served != nil {
		record.pinnedChain = served.CertPEM
	}
	return record, accessToken, nil
}

func (r *leaseRegistry) allocateRegisterTransportsLocked(record *leaseRecord, req types.RegisterChallengeRequest) error {
	if req.UDPEnabled {
		port, err := r.udpPorts.allocate(record)
		if err != nil {
			return errUDPPortExhausted
		}
		record.datagram = transport.NewRelayDatagram(record.ServiceKey(), port)
	}
	if req.TCPEnabled {
		port, err := r.tcpPorts.allocate(record)
		if err != nil {
			return errTCPPortExhausted
		}
		record.tcpPort = port
	}
	return nil
}

func (r *leaseRegistry) countRegisterCapacityLocked(record *leaseRecord, now time.Time) (int, int) {
	identityKey := record.ServiceKey()
	udpLeases := 0
	tcpLeases := 0
	for _, existing := range r.records {
		if existing == nil || existing.isExpired(now) {
			continue
		}
		if existing.ServiceKey() != identityKey {
			if existing.datagram != nil {
				udpLeases++
			}
			if existing.tcpPort > 0 {
				tcpLeases++
			}
		}
	}
	return udpLeases, tcpLeases
}

func (r *leaseRegistry) checkRegisterCapacityLocked(record *leaseRecord, now time.Time) error {
	udpLeases, tcpLeases := r.countRegisterCapacityLocked(record, now)
	if record.datagram != nil {
		if max := r.udpMaxLeases; max > 0 && udpLeases >= max {
			return errUDPCapacityExceeded
		}
	}
	if record.tcpPort > 0 {
		if max := r.tcpMaxLeases; max > 0 && tcpLeases >= max {
			return errTCPPortCapacityExceeded
		}
	}
	return nil
}

func (r *leaseRegistry) findRegisterReplacedLocked(identityKey types.ServiceIdentityKey) int {
	for i, existing := range r.records {
		if existing == nil {
			continue
		}
		if existing.reverse != nil && existing.ServiceKey() == identityKey {
			return i
		}
	}
	return -1
}
func (r *leaseRegistry) resolveHostnameConflictLocked(record *leaseRecord, existingHostname string, req types.RegisterChallengeRequest) error {
	if existingHostname == "" || existingHostname != record.Hostname {
		return nil
	}
	if !req.AllowCanonicalFallback {
		return errHostnameConflict
	}
	record.Hostname = ""
	return nil
}

func (r *leaseRegistry) checkRegisterHostnameLocked(record *leaseRecord, identityKey types.ServiceIdentityKey, req types.RegisterChallengeRequest, now time.Time) error {
	for _, existing := range r.records {
		if existing == nil || existing.isExpired(now) {
			continue
		}
		if existing.ServiceKey() == identityKey || !existing.isPublicEntry() {
			continue
		}
		if existing.CanonicalHostname == record.CanonicalHostname {
			return errHostnameConflict
		}
		if err := r.resolveHostnameConflictLocked(record, existing.Hostname, req); err != nil {
			return err
		}
	}
	return nil
}

func (r *leaseRegistry) pruneRegisterPendingLocked(record *leaseRecord, identityKey types.ServiceIdentityKey) {
	for i := 0; i < len(r.records); i++ {
		existing := r.records[i]
		if existing == nil || existing.reverse != nil || !existing.isPublicEntry() || existing.ServiceKey() != identityKey {
			continue
		}
		if existing.CanonicalHostname == record.CanonicalHostname {
			r.deleteRecord(i)
			i--
		}
	}
}

func (r *leaseRegistry) insertRegisterRecordLocked(record *leaseRecord, req types.RegisterChallengeRequest, replacedIndex int, now time.Time) *leaseRecord {
	r.cache.Register(record.cacheLeaseLocked(), req)
	if replacedIndex < 0 {
		r.records = append(r.records, record)
		return nil
	}
	replaced := r.records[replacedIndex]
	if !replaced.isExpired(now) && !replaced.FirstSeenAt.IsZero() && replaced.FirstSeenAt.Before(record.FirstSeenAt) {
		record.FirstSeenAt = replaced.FirstSeenAt
	}
	r.bps.ResetIdentityLimiter(record.ServiceKey())
	r.records[replacedIndex] = record
	return replaced
}

func (r *leaseRegistry) closeRegisterReplaced(replaced *leaseRecord) {
	if replaced == nil {
		return
	}
	if r.overlay != nil {
		r.overlay.ForgetLease(replaced.id)
	}
	r.closeRecord(replaced)
}

func (r *leaseRegistry) removeRegisterRecordLocked(record *leaseRecord, identityKey types.ServiceIdentityKey) {
	for i, current := range r.records {
		if current == record {
			r.deleteRecord(i)
			r.bps.ResetIdentityLimiter(identityKey)
			break
		}
	}
}

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, sourceAddr netip.Addr, reportedIP string, self types.RelayDescriptor, descriptors []types.RelayDescriptor, served *acme.TLSMaterial) (*leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	record, accessToken, err := r.buildRegisterRecord(req, sourceAddr, reportedIP, served)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	identityKey := record.ServiceKey()

	r.mu.Lock()
	if err := r.allocateRegisterTransportsLocked(record, req); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}
	r.mu.Unlock()

	if err := record.Start(); err != nil {
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}

	r.mu.Lock()
	now := time.Now()
	replacedIndex := r.findRegisterReplacedLocked(identityKey)
	if err := r.checkRegisterHostnameLocked(record, identityKey, req, now); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}
	if err := r.checkRegisterCapacityLocked(record, now); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}
	r.pruneRegisterPendingLocked(record, identityKey)
	replaced := r.insertRegisterRecordLocked(record, req, replacedIndex, now)
	r.mu.Unlock()

	r.closeRegisterReplaced(replaced)

	reverseEndpoint, err := r.issueReverseEndpoint(reverseEndpointInput{
		leaseIdentity: record.Identity,
		leaseID:       record.id,
		expiresAt:     record.ExpiresAt,
		useOverlay:    record.Overlay,
	}, self, descriptors)
	if err != nil {
		r.mu.Lock()
		r.removeRegisterRecordLocked(record, identityKey)
		r.mu.Unlock()
		if r.overlay != nil {
			r.overlay.ForgetLease(record.id)
		}
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}

	return record, formatRegisterResponse(record, accessToken, reverseEndpoint), nil
}
