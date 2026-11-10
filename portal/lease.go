package portal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errLeaseTokenAuthorityIsRequired        = errors.New("lease token authority is required")
	errLeaseTokenAuthorityPublicKeyRequired = errors.New("lease token authority public key is required")
	errLeaseTokenIssuerMustAbsoluteURL      = errors.New("lease token issuer must be an absolute URL")
)

const (
	defaultLeaseTTL                          = 2 * time.Minute
	maxLeaseTTL                              = 10 * time.Minute
	defaultRegisterChallengeTTL              = 2 * time.Minute
	defaultRegisterChallengeOutstandingPerIP = 32
	defaultRegisterChallengeOutstanding      = 256
	defaultPortReservationGrace              = 5 * time.Minute
	defaultIdleKeepalive                     = 15 * time.Second
	maxClaimedStartedAge                     = 7 * 24 * time.Hour
	defaultReadyQueueLimit                   = 8
	defaultLeaseBridgeLimit                  = 128
)

func requestedLeaseTTL(seconds int) (time.Duration, error) {
	if seconds <= 0 {
		return defaultLeaseTTL, nil
	}
	if seconds > int(maxLeaseTTL/time.Second) {
		return 0, errLeaseTTLExceeded
	}
	return time.Duration(seconds) * time.Second, nil
}

type leaseRegistry struct {
	records        []*leaseRecord
	rootHostname   string
	tokenAuthority identity.Authority
	tokenIssuer    string
	reverseURL     string
	overlay        *overlay.Runtime
	cache          *cache.Manager
	bps            *BPSManager
	udpPorts       portPool
	tcpPorts       portPool
	bindings       *keyless.BindingRegistry

	blocked        map[types.ServiceIdentityKey]blockedIdentity
	accessRevision uint64

	udpEnabled, tcpPortEnabled bool
	udpMaxLeases, tcpMaxLeases int
	unapprovedPerSource        int

	mu sync.RWMutex
}

type blockedIdentity struct {
	pushedAt time.Time
	refusal  *apiError
}

func newLeaseRegistry(minPort, maxPort int, rootHostname string, tokenAuthority identity.Authority, tokenIssuer string, defaultIdentityBPS int64) (*leaseRegistry, error) {
	if tokenAuthority == nil {
		return nil, errLeaseTokenAuthorityIsRequired
	}
	tokenIdentity := tokenAuthority.Identity()
	if strings.TrimSpace(tokenIdentity.PublicKey) == "" {
		return nil, errLeaseTokenAuthorityPublicKeyRequired
	}
	issuerURL, err := url.Parse(strings.TrimSpace(tokenIssuer))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errLeaseTokenIssuerMustAbsoluteURL, err)
	}
	if issuerURL.Host == "" {
		return nil, errLeaseTokenIssuerMustAbsoluteURL
	}

	return &leaseRegistry{
		records:        make([]*leaseRecord, 0),
		rootHostname:   utils.NormalizeHostname(rootHostname),
		tokenAuthority: tokenAuthority,
		tokenIssuer:    tokenIssuer,
		reverseURL:     utils.ResolveAPIURL(issuerURL, types.PathSDKConnect).String(),
		bps:            NewBPSManager(defaultIdentityBPS),
		blocked:        make(map[types.ServiceIdentityKey]blockedIdentity),
		udpPorts:       newPortPool(minPort, maxPort, defaultPortReservationGrace),
		tcpPorts:       newPortPool(minPort, maxPort, defaultPortReservationGrace),
		bindings:       keyless.NewBindingRegistry(5 * time.Minute),
	}, nil
}

func (r *leaseRegistry) setTransportPolicy(udpEnabled bool, udpMaxLeases int, tcpEnabled bool, tcpMaxLeases int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.udpEnabled = udpEnabled
	r.udpMaxLeases = udpMaxLeases
	r.tcpPortEnabled = tcpEnabled
	r.tcpMaxLeases = tcpMaxLeases
}

func (r *leaseRegistry) udpPolicy() (bool, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.udpEnabled, r.udpMaxLeases
}

func (r *leaseRegistry) tcpPortPolicy() (bool, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tcpPortEnabled, r.tcpMaxLeases
}

func (r *leaseRegistry) setIdentityAccess(key types.ServiceIdentityKey, access types.LeaseAccess, revision uint64) bool {
	if r == nil || !key.Valid() {
		return true
	}
	r.mu.Lock()
	if revision < r.accessRevision {
		r.mu.Unlock()
		return false
	}
	r.accessRevision = revision
	r.applyIdentityAccessLocked(key, access)
	var closeIdle []func()
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.ServiceKey() != key {
			continue
		}
		if access == types.LeaseRoutable {
			record.reverse.Resume()
		} else if closeStreams := record.reverse.Pause(); closeStreams != nil {
			closeIdle = append(closeIdle, closeStreams)
		}
	}
	r.mu.Unlock()
	for _, closeStreams := range closeIdle {
		closeStreams()
	}
	return true
}

func (r *leaseRegistry) suspendIdentity(key types.ServiceIdentityKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyIdentityAccessLocked(key, types.LeasePending)
}

func (r *leaseRegistry) applyIdentityAccessLocked(key types.ServiceIdentityKey, access types.LeaseAccess) {
	routable := access == types.LeaseRoutable
	switch access {
	case types.LeaseRoutable:
		delete(r.blocked, key)
	case types.LeaseDenied:
		r.blocked[key] = blockedIdentity{pushedAt: time.Now(), refusal: errLeaseDenied}
	default:
		r.blocked[key] = blockedIdentity{pushedAt: time.Now(), refusal: errLeaseRejected}
	}
	for _, record := range r.records {
		if record == nil || record.ServiceKey() != key {
			continue
		}
		if record.datagram != nil {
			record.datagram.SetEnabled(routable)
		}
		if !routable {
			record.mu.Lock()
			record.revokeBridgesLocked()
			record.mu.Unlock()
		}
	}
	if !routable {
		r.cache.DetachOwner(key)
	}
}

func (r *leaseRegistry) isRoutable(key types.ServiceIdentityKey) bool {
	if r == nil || !key.Valid() {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isRoutableLocked(key)
}

func (r *leaseRegistry) isRoutableLocked(key types.ServiceIdentityKey) bool {
	_, blocked := r.blocked[key]
	return !blocked
}

func (r *leaseRegistry) admitBridge(ctx context.Context, record *leaseRecord, inbound net.Conn) (*leaseBridge, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if record == nil || r.recordByLease(record.ServiceKey(), record.id, time.Now()) != record {
		return nil, errLeaseNotFound
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return nil, errLeaseRejected
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.closed || ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if len(record.bridges) >= defaultLeaseBridgeLimit {
		return nil, errLeaseRejected
	}
	ctx, cancel := context.WithCancel(ctx)
	bridge := &leaseBridge{ctx: ctx, cancel: cancel, inbound: inbound}
	if record.bridges == nil {
		record.bridges = make(map[*leaseBridge]struct{})
	}
	record.bridges[bridge] = struct{}{}
	return bridge, nil
}

func (r *leaseRegistry) activateBridge(record *leaseRecord, bridge *leaseBridge, reverse net.Conn) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.recordByLease(record.ServiceKey(), record.id, time.Now()) != record {
		return errLeaseNotFound
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return errLeaseRejected
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if _, exists := record.bridges[bridge]; !exists || record.closed || bridge.ctx.Err() != nil {
		return net.ErrClosed
	}
	bridge.reverse = reverse
	return nil
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	out := r.records
	for _, record := range out {
		if record != nil && record.reverse != nil {
			r.bps.ResetIdentityLimiter(record.ServiceKey())
		}
		if record != nil && r.overlay != nil {
			r.overlay.ForgetLease(record.id)
		}
	}
	r.records = nil
	r.mu.Unlock()

	for _, record := range out {
		r.closeRecord(record)
	}
	return out
}

func (r *leaseRegistry) Lookup(host string) (*leaseRecord, bool) {
	host = utils.NormalizeHostname(host)
	if host == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	var wildcard *leaseRecord
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		for _, hostname := range record.hostnames() {
			if hostname == host {
				return record, true
			}
			if wildcard == nil && utils.HostnameMatchesPattern(hostname, host) {
				wildcard = record
			}
		}
	}
	if wildcard != nil {
		return wildcard, true
	}
	return nil, false
}

func (r *leaseRegistry) recordByKey(key types.ServiceIdentityKey, now time.Time) *leaseRecord {
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.isExpired(now) {
			continue
		}
		if record.ServiceKey() == key {
			return record
		}
	}
	return nil
}

func (r *leaseRegistry) recordByLease(key types.ServiceIdentityKey, leaseID string, now time.Time) *leaseRecord {
	record := r.recordByKey(key, now)
	if record == nil || record.id != leaseID {
		return nil
	}
	return record
}

func (r *leaseRegistry) recordForVerifiedLeaseLocked(key types.ServiceIdentityKey, leaseID string, now time.Time) (*leaseRecord, error) {
	record := r.recordByKey(key, now)
	if record == nil {
		return nil, errLeaseNotFound
	}
	if record.id != leaseID {
		return nil, errUnauthorized
	}
	return record, nil
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
		switch {
		case record.registerChallenge != nil && record.sourceAddr == source:
			if record.registerChallenge.ChallengeID == challengeID {
				issued = i
			}
			holder = record.registerChallenge.Request.Identity.ServiceKey()
		case record.reverse != nil && record.registerSource == source:
			holder = record.ServiceKey()
		default:
			continue
		}
		if holder != key && !r.isRoutableLocked(holder) {
			held[holder] = struct{}{}
		}
	}
	if len(held) < r.unapprovedPerSource {
		return nil
	}
	if issued >= 0 {
		r.deleteRecord(issued)
	}
	return errUnapprovedLeaseLimit
}

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, sourceAddr netip.Addr, reportedIP string, self types.RelayDescriptor, descriptors []types.RelayDescriptor, served *acme.TLSMaterial) (*leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	if err := req.Metadata.Validate(); err != nil {
		return nil, types.RegisterResponse{}, err
	}
	leaseIdentity := req.Identity

	ttl, err := requestedLeaseTTL(req.TTL)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}

	identityKey := leaseIdentity.ServiceKey()
	var publicHostname string
	if leaseIdentity.Name != "" {
		var err error
		publicHostname, err = utils.LeaseHostname(leaseIdentity.Name, r.rootHostname)
		if err != nil {
			return nil, types.RegisterResponse{}, err
		}
	}
	canonicalHostname, err := utils.CanonicalLeaseHostname(leaseIdentity.Name, leaseIdentity.Address, r.rootHostname)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	udpEnabled, _ := r.udpPolicy()
	tcpPortEnabled, _ := r.tcpPortPolicy()
	if req.UDPEnabled && !udpEnabled {
		return nil, types.RegisterResponse{}, errUDPDisabled
	}
	if req.TCPEnabled && !tcpPortEnabled {
		return nil, types.RegisterResponse{}, errTCPPortDisabled
	}

	leaseID := utils.RandomID("lease_")
	accessToken, claims, err := identity.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, leaseIdentity, leaseID, ttl)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()
	firstSeenAt := issuedAt
	if !req.StartedAt.IsZero() && req.StartedAt.Before(issuedAt) {
		firstSeenAt = req.StartedAt.UTC()
		if floor := issuedAt.Add(-maxClaimedStartedAge); firstSeenAt.Before(floor) {
			firstSeenAt = floor
		}
	}

	record := &leaseRecord{
		Identity:          leaseIdentity,
		id:                leaseID,
		Hostname:          publicHostname,
		CanonicalHostname: canonicalHostname,
		Metadata:          req.Metadata.Copy(),
		Overlay:           req.Overlay,
		ExpiresAt:         expiresAt,
		FirstSeenAt:       firstSeenAt,
		LastSeenAt:        issuedAt,
		sourceAddr:        sourceAddr,
		registerSource:    sourceAddr,
		ReportedIP:        utils.SanitizeReportedIP(reportedIP),
		reverse:           transport.NewReversePool(defaultIdleKeepalive, defaultReadyQueueLimit),
	}
	if served != nil {
		record.pinnedChain = served.CertPEM
	}

	r.mu.Lock()
	if req.UDPEnabled {
		port, err := r.udpPorts.allocate(record)
		if err != nil {
			r.mu.Unlock()
			r.rollbackRecord(record)
			return nil, types.RegisterResponse{}, errUDPPortExhausted
		}
		record.datagram = transport.NewRelayDatagram(identityKey, port)
	}

	if req.TCPEnabled {
		port, err := r.tcpPorts.allocate(record)
		if err != nil {
			r.mu.Unlock()
			r.rollbackRecord(record)
			return nil, types.RegisterResponse{}, errTCPPortExhausted
		}
		record.tcpPort = port
	}
	r.mu.Unlock()

	if err := record.Start(); err != nil {
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}
	var replaced *leaseRecord
	replacedIndex := -1
	r.mu.Lock()
	now := time.Now()
	udpLeases := 0
	tcpLeases := 0
	for i, existing := range r.records {
		if existing == nil {
			continue
		}
		existingKey := existing.ServiceKey()
		if replacedIndex < 0 && existing.reverse != nil && existingKey == identityKey {
			replaced = existing
			replacedIndex = i
		}
		if existing.isExpired(now) {
			continue
		}
		if existingKey != identityKey {
			if existing.datagram != nil {
				udpLeases++
			}
			if existing.tcpPort > 0 {
				tcpLeases++
			}
		}
		if existing.isPublicEntry() && existingKey != identityKey {
			if existing.CanonicalHostname == record.CanonicalHostname {
				r.mu.Unlock()
				r.rollbackRecord(record)
				return nil, types.RegisterResponse{}, errHostnameConflict
			}
			if existing.Hostname != "" && existing.Hostname == record.Hostname {
				if !req.AllowCanonicalFallback {
					r.mu.Unlock()
					r.rollbackRecord(record)
					return nil, types.RegisterResponse{}, errHostnameConflict
				}
				record.Hostname = ""
			}
		}
	}
	if record.datagram != nil {
		if max := r.udpMaxLeases; max > 0 && udpLeases >= max {
			r.mu.Unlock()
			r.rollbackRecord(record)
			return nil, types.RegisterResponse{}, errUDPCapacityExceeded
		}
	}
	if record.tcpPort > 0 {
		if max := r.tcpMaxLeases; max > 0 && tcpLeases >= max {
			r.mu.Unlock()
			r.rollbackRecord(record)
			return nil, types.RegisterResponse{}, errTCPPortCapacityExceeded
		}
	}
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
	r.cache.Register(record.cacheLeaseLocked(), req)
	if replacedIndex >= 0 {
		if !replaced.isExpired(now) && !replaced.FirstSeenAt.IsZero() && replaced.FirstSeenAt.Before(record.FirstSeenAt) {
			record.FirstSeenAt = replaced.FirstSeenAt
		}
		r.bps.ResetIdentityLimiter(identityKey)
		r.records[replacedIndex] = record
	} else {
		r.records = append(r.records, record)
	}
	r.mu.Unlock()

	if replaced != nil {
		if r.overlay != nil {
			r.overlay.ForgetLease(replaced.id)
		}
		r.closeRecord(replaced)
	}
	reverseEndpoint, err := r.issueReverseEndpoint(reverseEndpointInput{
		leaseIdentity: leaseIdentity,
		leaseID:       leaseID,
		expiresAt:     expiresAt,
		useOverlay:    req.Overlay,
	}, self, descriptors)
	if err != nil {
		r.mu.Lock()
		for i, current := range r.records {
			if current == record {
				r.deleteRecord(i)
				r.bps.ResetIdentityLimiter(identityKey)
				break
			}
		}
		r.mu.Unlock()
		if r.overlay != nil {
			r.overlay.ForgetLease(leaseID)
		}
		r.rollbackRecord(record)
		return nil, types.RegisterResponse{}, err
	}

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
	return record, resp, nil
}

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

func (r *leaseRegistry) Renew(req types.RenewRequest, sourceAddr netip.Addr, current *acme.TLSMaterial) (types.RenewResponse, reverseEndpointInput, error) {
	if r == nil {
		return types.RenewResponse{}, reverseEndpointInput{}, errFeatureUnavailable
	}
	claims, err := identity.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, errUnauthorized
	}
	if err := req.Metadata.Validate(); err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, err
	}
	ttl, err := requestedLeaseTTL(req.TTL)
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, err
	}

	leaseKey := claims.Identity.ServiceKey()
	reportedIP := utils.SanitizeReportedIP(req.ReportedIP)
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

	now := time.Now()
	expiresAt := now.Add(ttl).UTC().Truncate(time.Second)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if sourceAddr.IsValid() {
		record.sourceAddr = sourceAddr
	}
	if strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	record.Metadata = req.Metadata.Copy()
	r.cache.Renew(record.cacheLeaseLocked())
	recordIdentity := record.Identity
	leaseID := record.id
	useOverlay := record.Overlay
	r.mu.Unlock()

	nextAccessToken, _, err := identity.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, recordIdentity, leaseID, ttl)
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, &apiError{types.APIErrorCodeInternal, err.Error(), http.StatusInternalServerError}
	}

	reverseInput := reverseEndpointInput{
		leaseIdentity: recordIdentity,
		leaseID:       leaseID,
		expiresAt:     expiresAt,
		useOverlay:    useOverlay,
	}
	return types.RenewResponse{
		ExpiresAt:   expiresAt,
		AccessToken: nextAccessToken,
	}, reverseInput, nil
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

func (r *leaseRegistry) issueReverseEndpoint(input reverseEndpointInput, self types.RelayDescriptor, descriptors []types.RelayDescriptor) (types.ReverseEndpoint, error) {
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

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string, sourceAddr netip.Addr) (types.RegisterChallengeResponse, error) {
	if r == nil {
		return types.RegisterChallengeResponse{}, errFeatureUnavailable
	}
	if _, err := requestedLeaseTTL(req.TTL); err != nil {
		return types.RegisterChallengeResponse{}, err
	}

	now := time.Now().UTC()
	challenge, err := identity.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	if _, err := utils.CanonicalLeaseHostname(challenge.Request.Identity.Name, challenge.Request.Identity.Address, r.rootHostname); err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	pending := 0
	globalPending := 0
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record == nil || record.registerChallenge == nil {
			i++
			continue
		}
		if record.isExpired(now) {
			r.deleteRecord(i)
			continue
		}
		globalPending++
		if record.sourceAddr == sourceAddr {
			pending++
		}
		i++
	}
	if pending >= defaultRegisterChallengeOutstandingPerIP || globalPending >= defaultRegisterChallengeOutstanding {
		return types.RegisterChallengeResponse{}, errRegisterChallengePending
	}
	r.records = append(r.records, &leaseRecord{
		ExpiresAt:         challenge.ExpiresAt,
		sourceAddr:        sourceAddr,
		registerChallenge: challenge,
	})

	return types.RegisterChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (r *leaseRegistry) consumeVerifiedRegisterChallenge(req types.RegisterRequest) (*identity.RegisterChallenge, netip.Addr, error) {
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return nil, netip.Addr{}, identity.ErrRegisterChallengeNotFound
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, record := range r.records {
		if record == nil || record.registerChallenge == nil || record.registerChallenge.ChallengeID != challengeID {
			continue
		}
		challenge, source := record.registerChallenge, record.sourceAddr
		if challenge.Expired(now) {
			r.deleteRecord(i)
			return nil, netip.Addr{}, identity.ErrRegisterChallengeExpired
		}
		if err := challenge.Verify(req, now); err != nil {
			return nil, netip.Addr{}, err
		}

		r.deleteRecord(i)
		return challenge, source, nil
	}
	return nil, netip.Addr{}, identity.ErrRegisterChallengeNotFound
}

func (r *leaseRegistry) verifySigningAccessTokenLease(req *http.Request) (string, bool) {
	now := time.Now().UTC()
	claims, err := identity.VerifyLeaseAccessToken(req.Header.Get(types.HeaderAccessToken), r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return "", false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record, err := r.recordForVerifiedLeaseLocked(claims.Identity.ServiceKey(), claims.LeaseID, now)
	if err != nil {
		return "", false
	}
	if !record.isPublicEntry() {
		return "", false
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return "", false
	}
	return claims.LeaseID, true
}

func (r *leaseRegistry) Touch(key types.ServiceIdentityKey, sourceAddr netip.Addr, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record := r.recordByKey(key, now)
	if record == nil {
		return
	}
	record.LastSeenAt = now
	if sourceAddr.IsValid() {
		record.sourceAddr = sourceAddr
	}
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()

	var expired []*leaseRecord
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record != nil && record.isExpired(now) {
			expired = append(expired, record)
			if record.reverse != nil {
				r.bps.ResetIdentityLimiter(record.ServiceKey())
			}
			r.deleteRecord(i)
			continue
		}
		i++
	}
	for key, blocked := range r.blocked {
		if now.Sub(blocked.pushedAt) <= defaultRegisterChallengeTTL {
			continue
		}
		if r.recordByKey(key, now) == nil {
			delete(r.blocked, key)
		}
	}
	r.mu.Unlock()

	for _, record := range expired {
		r.closeRecord(record)
	}
	return expired
}

func (r *leaseRegistry) PublicLeases(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	leases := make([]types.Lease, 0, len(r.records))
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		if record.Metadata.Hide {
			continue
		}
		if record.reverse == nil {
			leases = append(leases, r.publicLease(record))
			continue
		}
		if !r.isRoutableLocked(record.ServiceKey()) {
			continue
		}
		since := time.Duration(0)
		if !record.LastSeenAt.IsZero() {
			since = max(now.Sub(record.LastSeenAt), 0)
		}
		if record.reverse.ReadyCount() == 0 && since >= 3*time.Minute {
			continue
		}
		leases = append(leases, r.publicLease(record))
	}
	return leases
}

func (r *leaseRegistry) PolicyLeases(now time.Time) []types.PolicyLease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	leases := make([]types.PolicyLease, 0, len(r.records))
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.isExpired(now) {
			continue
		}
		clientIP := "<unknown>"
		if record.sourceAddr.IsValid() {
			clientIP = record.sourceAddr.String()
		}
		identityKey := record.ServiceKey()
		serializedIdentityKey := identityKey.String()
		leases = append(leases, types.PolicyLease{
			Lease:       r.publicLease(record),
			IdentityKey: serializedIdentityKey,
			BPS:         r.bps.IdentityBPS(identityKey),
			ClientIP:    clientIP,
			ReportedIP:  record.ReportedIP,
		})
	}
	return leases
}

func (r *leaseRegistry) stats(now time.Time) (activeLeases, activeUDPFlows int64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, record := range r.records {
		if record == nil || record.reverse == nil || record.isExpired(now) {
			continue
		}
		activeLeases++
		if record.datagram != nil {
			activeUDPFlows += record.datagram.ActiveFlowCount()
		}
	}
	return activeLeases, activeUDPFlows
}

func (r *leaseRegistry) deleteRecord(i int) {
	if record := r.records[i]; record != nil {
		r.cache.Detach(record.cacheLeaseLocked())
	}
	if record := r.records[i]; record != nil && r.overlay != nil {
		r.overlay.ForgetLease(record.id)
	}
	last := len(r.records) - 1
	r.records[i] = r.records[last]
	r.records[last] = nil
	r.records = r.records[:last]
}

func (r *leaseRegistry) publicLease(record *leaseRecord) types.Lease {
	lease := types.Lease{
		Name:              record.Name,
		Address:           record.Address,
		ExpiresAt:         record.ExpiresAt,
		FirstSeenAt:       record.FirstSeenAt,
		LastSeenAt:        record.LastSeenAt,
		Hostname:          record.Hostname,
		CanonicalHostname: record.CanonicalHostname,
		UDPEnabled:        record.datagram != nil,
		TCPEnabled:        record.tcpPort > 0,
		Metadata:          record.Metadata.Copy(),
	}
	if record.tcpPort > 0 {
		lease.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort)
	}
	if record.datagram != nil {
		lease.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.reverse != nil {
		lease.Ready = record.reverse.ReadyCount()
	}
	return lease
}

func (r *leaseRegistry) closeRecord(record *leaseRecord) {
	if record == nil {
		return
	}
	record.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.datagram != nil {
		r.udpPorts.release(record.datagram.UDPPort(), record)
	}
	if record.tcpPort > 0 {
		r.tcpPorts.release(record.tcpPort, record)
	}
}

func (r *leaseRegistry) rollbackRecord(record *leaseRecord) {
	if record == nil {
		return
	}
	record.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.datagram != nil {
		r.udpPorts.rollback(record.datagram.UDPPort(), record)
	}
	if record.tcpPort > 0 {
		r.tcpPorts.rollback(record.tcpPort, record)
	}
}

var errPortExhausted = errors.New("no ports available")

type portReservation struct {
	port      int
	expiresAt time.Time
}

type portAllocation struct {
	record      *leaseRecord
	reservation portReservation
}

// portPool is registry-owned reservation metadata; all access holds leaseRegistry.mu.
type portPool struct {
	available []int
	inUse     map[int]portAllocation
	reserved  map[types.ServiceIdentityKey]portReservation
	grace     time.Duration
}

func newPortPool(min, max int, grace time.Duration) portPool {
	if min <= 0 || max <= 0 || min > max {
		return portPool{
			inUse:    make(map[int]portAllocation),
			reserved: make(map[types.ServiceIdentityKey]portReservation),
			grace:    grace,
		}
	}

	available := make([]int, 0, max-min+1)
	for port := min; port <= max; port++ {
		available = append(available, port)
	}
	return portPool{
		available: available,
		inUse:     make(map[int]portAllocation),
		reserved:  make(map[types.ServiceIdentityKey]portReservation),
		grace:     grace,
	}
}

func (a *portPool) allocate(record *leaseRecord) (int, error) {
	a.cleanupExpired(time.Now())

	key := record.ServiceKey()
	if res, ok := a.reserved[key]; ok {
		delete(a.reserved, key)
		a.inUse[res.port] = portAllocation{record: record, reservation: res}
		return res.port, nil
	}

	if len(a.available) == 0 {
		return 0, errPortExhausted
	}

	port := a.available[0]
	a.available = a.available[1:]
	a.inUse[port] = portAllocation{record: record}
	return port, nil
}

func (a *portPool) rollback(port int, record *leaseRecord) {
	allocation, ok := a.inUse[port]
	if !ok || allocation.record != record {
		return
	}
	delete(a.inUse, port)
	key := record.ServiceKey()
	if res := allocation.reservation; res.port != 0 && time.Now().Before(res.expiresAt) {
		if _, exists := a.reserved[key]; !exists {
			a.reserved[key] = res
			return
		}
	}
	a.available = append(a.available, port)
}

func (a *portPool) release(port int, record *leaseRecord) {
	owner, ok := a.inUse[port]
	if !ok || owner.record != record {
		return
	}
	delete(a.inUse, port)
	key := record.ServiceKey()

	if prev, exists := a.reserved[key]; exists {
		a.available = append(a.available, prev.port)
	}

	a.reserved[key] = portReservation{
		port:      port,
		expiresAt: time.Now().Add(a.grace),
	}
	a.cleanupExpired(time.Now())
}

func (a *portPool) cleanupExpired(now time.Time) {
	for key, res := range a.reserved {
		if now.After(res.expiresAt) {
			delete(a.reserved, key)
			a.available = append(a.available, res.port)
		}
	}
}
