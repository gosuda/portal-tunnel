package portal

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultLeaseTTL                          = 2 * time.Minute
	defaultRegisterChallengeTTL              = 2 * time.Minute
	defaultRegisterChallengeOutstandingPerIP = 32
	defaultPortReservationGrace              = 5 * time.Minute
	defaultIdleKeepalive                     = 15 * time.Second
	defaultReadyQueueLimit                   = 8
)

type leaseRegistry struct {
	records        []*leaseRecord
	rootHostname   string
	tokenAuthority identity.Authority
	tokenIssuer    string
	reverseURL     string
	overlay        *overlay.Runtime
	cache          *cache.Manager
	bps            *BPSManager
	udpPorts       *transport.PortAllocator
	tcpPorts       *transport.PortAllocator
	bindings       *keyless.BindingRegistry

	// blocked holds the relay-pushed access results for identities the relay
	// does not route. Presence is the decision; the timestamp bounds stale
	// entries for identities whose registration never completed.
	blocked map[string]time.Time
	// Access revisions describe complete relay snapshots, so the newest
	// observed revision fences older publications for every identity. Keep
	// this watermark when idle blocked entries expire to prevent stale replay.
	accessRevision uint64

	udpEnabled, tcpPortEnabled bool
	udpMaxLeases, tcpMaxLeases int

	mu sync.RWMutex
}

func newLeaseRegistry(minPort, maxPort int, rootHostname string, tokenAuthority identity.Authority, tokenIssuer string) (*leaseRegistry, error) {
	if tokenAuthority == nil {
		return nil, errors.New("lease token authority is required")
	}
	tokenIdentity := tokenAuthority.Identity()
	if strings.TrimSpace(tokenIdentity.PublicKey) == "" {
		return nil, errors.New("lease token authority public key is required")
	}
	issuerURL, err := url.Parse(strings.TrimSpace(tokenIssuer))
	if err != nil || issuerURL.Host == "" {
		return nil, errors.New("lease token issuer must be an absolute URL")
	}

	return &leaseRegistry{
		records:        make([]*leaseRecord, 0),
		rootHostname:   utils.NormalizeHostname(rootHostname),
		tokenAuthority: tokenAuthority,
		tokenIssuer:    tokenIssuer,
		reverseURL:     utils.ResolveAPIURL(issuerURL, types.PathSDKConnect).String(),
		bps:            NewBPSManager(),
		blocked:        make(map[string]time.Time),
		udpPorts:       transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		tcpPorts:       transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		bindings:       keyless.NewBindingRegistry(5 * time.Minute),
	}, nil
}

// setUDPPolicy and setTCPPortPolicy apply the relay's current transport
// capacity values; the relay owns the operator decisions behind them.
func (r *leaseRegistry) setUDPPolicy(enabled bool, maxLeases int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.udpEnabled = enabled
	r.udpMaxLeases = maxLeases
}

func (r *leaseRegistry) setTCPPortPolicy(enabled bool, maxLeases int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tcpPortEnabled = enabled
	r.tcpMaxLeases = maxLeases
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

// setIdentityRoutable applies the relay-pushed access result for one
// identity. A non-routable identity also loses its cached content
// immediately: cached sites must never outlive the relay's decision to route
// their owner.
func (r *leaseRegistry) setIdentityRoutable(key string, routable bool, revision uint64) bool {
	if r == nil || key == "" {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if revision < r.accessRevision {
		return false
	}
	r.accessRevision = revision
	r.applyIdentityRoutableLocked(key, routable)
	return true
}

// suspendIdentity keeps registration fail-closed without inventing a relay
// revision. Only a publication at the current or a newer revision can reopen it.
func (r *leaseRegistry) suspendIdentity(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyIdentityRoutableLocked(key, false)
}

func (r *leaseRegistry) applyIdentityRoutableLocked(key string, routable bool) {
	if routable {
		delete(r.blocked, key)
	} else {
		r.blocked[key] = time.Now()
	}
	for _, record := range r.records {
		if record == nil || record.Key() != key {
			continue
		}
		if record.datagram != nil {
			record.datagram.SetRoutable(routable)
		}
		if record.tcpPort != nil {
			record.tcpPort.SetRoutable(routable)
		}
	}
	if !routable {
		// DetachOwner only changes cache metadata. Keep revocation ordered
		// with access publication so an older deny cannot detach newer content.
		r.cache.DetachOwner(key)
	}
}

func (r *leaseRegistry) isRoutable(key string) bool {
	if r == nil || key == "" {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isRoutableLocked(key)
}

// isRoutableLocked reads the pushed access result; the caller must hold r.mu.
func (r *leaseRegistry) isRoutableLocked(key string) bool {
	_, blocked := r.blocked[key]
	return !blocked
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	out := r.records
	for _, record := range out {
		if record != nil && record.stream != nil {
			r.bps.ResetIdentityLimiter(record.Key())
		}
		if record != nil && r.overlay != nil {
			r.overlay.ForgetLease(record.id)
		}
	}
	r.records = nil
	r.mu.Unlock()

	for _, record := range out {
		record.Close()
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
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		for _, hostname := range record.hostnames() {
			if hostname == host {
				return record, true
			}
		}
	}
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		for _, hostname := range record.hostnames() {
			if hostname != host && utils.HostnameMatchesPattern(hostname, host) {
				return record, true
			}
		}
	}
	return nil, false
}

func (r *leaseRegistry) recordByKey(key string, now time.Time) *leaseRecord {
	for _, record := range r.records {
		if record == nil || record.stream == nil || record.isExpired(now) {
			continue
		}
		if record.Key() == key {
			return record
		}
	}
	return nil
}

func (r *leaseRegistry) recordByLease(key, leaseID string, now time.Time) *leaseRecord {
	record := r.recordByKey(key, now)
	if record == nil || record.id != leaseID {
		return nil
	}
	return record
}

// containsLiveRecordLocked and ownsHostnameLocked read registry state while
// the caller holds r.mu.
func (r *leaseRegistry) containsLiveRecordLocked(want *leaseRecord, now time.Time) bool {
	if want == nil || want.isExpired(now) {
		return false
	}
	for _, record := range r.records {
		if record == want {
			return true
		}
	}
	return false
}

func (r *leaseRegistry) ownsHostnameLocked(hostname string, now time.Time) bool {
	for _, record := range r.records {
		if record == nil || record.isExpired(now) {
			continue
		}
		for _, current := range record.hostnames() {
			if current == hostname {
				return true
			}
		}
	}
	return false
}

// recordForVerifiedLease distinguishes a missing lease from a stale credential.
// The caller must already have verified the credential and must hold r.mu.
func (r *leaseRegistry) recordForVerifiedLease(key, leaseID string, now time.Time) (*leaseRecord, error) {
	record := r.recordByKey(key, now)
	if record == nil {
		return nil, errLeaseNotFound
	}
	if record.id != leaseID {
		return nil, errUnauthorized
	}
	return record, nil
}

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, clientIP, reportedIP string, self types.RelayDescriptor, descriptors []types.RelayDescriptor) (*leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	leaseIdentity := req.Identity

	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	identityKey := leaseIdentity.Key()
	publicHostname, err := utils.LeaseHostname(leaseIdentity.Name, r.rootHostname)
	if err != nil {
		return nil, types.RegisterResponse{}, err
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

	stream := transport.NewRelayStream(identityKey, defaultIdleKeepalive, defaultReadyQueueLimit)
	record := &leaseRecord{
		Identity:          leaseIdentity,
		id:                leaseID,
		Hostname:          publicHostname,
		CanonicalHostname: canonicalHostname,
		Metadata:          req.Metadata.Copy(),
		Overlay:           req.Overlay,
		ExpiresAt:         expiresAt,
		FirstSeenAt:       issuedAt,
		LastSeenAt:        issuedAt,
		ClientIP:          clientIP,
		ReportedIP:        utils.SanitizeReportedIP(reportedIP),
		stream:            stream,
	}

	if req.UDPEnabled {
		if r.udpPorts == nil {
			return nil, types.RegisterResponse{}, errors.New("udp port allocation not available")
		}
		port, err := r.udpPorts.Allocate(identityKey)
		if err != nil {
			if errors.Is(err, transport.ErrPortExhausted) {
				return nil, types.RegisterResponse{}, errUDPPortExhausted
			}
			return nil, types.RegisterResponse{}, err
		}
		record.datagram = transport.NewRelayDatagram(identityKey, port)
		record.udpPorts = r.udpPorts
	}

	if req.TCPEnabled {
		if r.tcpPorts == nil {
			record.Close()
			return nil, types.RegisterResponse{}, errors.New("tcp port allocation not available")
		}
		port, err := r.tcpPorts.Allocate(identityKey)
		if err != nil {
			record.Close()
			if errors.Is(err, transport.ErrPortExhausted) {
				return nil, types.RegisterResponse{}, errTCPPortExhausted
			}
			return nil, types.RegisterResponse{}, err
		}
		record.tcpPort = transport.NewRelayTCPPort(identityKey, port, stream)
		record.tcpPorts = r.tcpPorts
	}

	if err := record.Start(); err != nil {
		record.Close()
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
		existingKey := existing.Key()
		if replacedIndex < 0 && existing.stream != nil && existingKey == identityKey {
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
			if existing.tcpPort != nil {
				tcpLeases++
			}
		}
		if existing.isPublicEntry() && existingKey != identityKey {
			if existing.CanonicalHostname == record.CanonicalHostname {
				r.mu.Unlock()
				record.Close()
				return nil, types.RegisterResponse{}, errHostnameConflict
			}
			if existing.Hostname != "" && existing.Hostname == record.Hostname {
				record.Hostname = ""
			}
		}
	}
	if record.datagram != nil {
		if max := r.udpMaxLeases; max > 0 && udpLeases >= max {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errUDPCapacityExceeded
		}
	}
	if record.tcpPort != nil {
		if max := r.tcpMaxLeases; max > 0 && tcpLeases >= max {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errTCPPortCapacityExceeded
		}
	}
	for i := 0; i < len(r.records); i++ {
		existing := r.records[i]
		if existing == nil || existing.stream != nil || !existing.isPublicEntry() || existing.Key() != identityKey {
			continue
		}
		if existing.CanonicalHostname == record.CanonicalHostname {
			r.deleteRecord(i)
			i--
		}
	}
	r.cache.Register(record.cacheLease(), req)
	if replacedIndex >= 0 {
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
		replaced.Close()
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
		record.Close()
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
		TCPEnabled:        record.tcpPort != nil,
	}
	if record.datagram != nil {
		resp.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.tcpPort != nil {
		resp.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort.TCPPort())
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
	return r.admitLeaseIdentity(claims.Identity.Key(), claims.LeaseID, now, requireDatagram)
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
	return r.admitLeaseIdentity(claims.Identity.Key(), claims.LeaseID, now, false)
}

func (r *leaseRegistry) admitLeaseIdentity(key, leaseID string, now time.Time, requireDatagram bool) (*leaseRecord, error) {
	r.mu.RLock()
	record, err := r.recordForVerifiedLease(key, leaseID, now)
	r.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	if !r.isRoutable(record.Key()) {
		return nil, errLeaseRejected
	}
	if record.stream == nil || (requireDatagram && record.datagram == nil) {
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

func (r *leaseRegistry) Renew(req types.RenewRequest, clientIP string) (types.RenewResponse, reverseEndpointInput, error) {
	if r == nil {
		return types.RenewResponse{}, reverseEndpointInput{}, errFeatureUnavailable
	}
	claims, err := identity.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return types.RenewResponse{}, reverseEndpointInput{}, errUnauthorized
	}
	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	leaseKey := claims.Identity.Key()
	reportedIP := utils.SanitizeReportedIP(req.ReportedIP)
	r.mu.Lock()
	record, err := r.recordForVerifiedLease(leaseKey, claims.LeaseID, time.Time{})
	if err != nil {
		r.mu.Unlock()
		return types.RenewResponse{}, reverseEndpointInput{}, err
	}

	now := time.Now()
	expiresAt := now.Add(ttl).UTC().Truncate(time.Second)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	if strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	record.Metadata = req.Metadata.Copy()
	r.cache.Renew(record.cacheLease())
	recordIdentity := record.Identity
	leaseID := record.id
	useOverlay := record.Overlay
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
	_, activeErr := r.recordForVerifiedLease(input.leaseIdentity.Key(), input.leaseID, time.Now().UTC())
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
	record, err := r.recordForVerifiedLease(claims.Identity.Key(), claims.LeaseID, now)
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

	key := claims.Identity.Key()
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
		record.Close()
		return record, nil
	}
	r.mu.Unlock()
	return nil, errLeaseNotFound
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri, clientIP string) (types.RegisterChallengeResponse, error) {
	if r == nil {
		return types.RegisterChallengeResponse{}, errFeatureUnavailable
	}

	now := time.Now().UTC()
	challenge, err := identity.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	if _, err := utils.CanonicalLeaseHostname(challenge.Request.Identity.Name, challenge.Request.Identity.Address, r.rootHostname); err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	clientIP = strings.ToLower(strings.TrimSpace(clientIP))
	clientIP = cmp.Or(clientIP, "<unknown>")

	r.mu.Lock()
	defer r.mu.Unlock()

	pending := 0
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record != nil && record.registerChallenge != nil {
			if record.isExpired(now) {
				r.deleteRecord(i)
				continue
			}
			if record.ClientIP == clientIP {
				pending++
			}
		}
		i++
	}
	if pending >= defaultRegisterChallengeOutstandingPerIP {
		return types.RegisterChallengeResponse{}, errRegisterChallengePending
	}
	r.records = append(r.records, &leaseRecord{
		ExpiresAt:         challenge.ExpiresAt,
		ClientIP:          clientIP,
		registerChallenge: challenge,
	})

	return types.RegisterChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (r *leaseRegistry) consumeVerifiedRegisterChallenge(req types.RegisterRequest) (*identity.RegisterChallenge, error) {
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return nil, identity.ErrRegisterChallengeNotFound
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, record := range r.records {
		if record == nil || record.registerChallenge == nil || record.registerChallenge.ChallengeID != challengeID {
			continue
		}
		challenge := record.registerChallenge
		if challenge.Expired(now) {
			r.deleteRecord(i)
			return nil, identity.ErrRegisterChallengeExpired
		}
		if err := challenge.Verify(req, now); err != nil {
			return nil, err
		}

		r.deleteRecord(i)
		return challenge, nil
	}
	return nil, identity.ErrRegisterChallengeNotFound
}

// verifySigningAccessTokenLease authenticates the access-token header of a
// /v1/sign request and returns the live, routable lease it belongs to. The
// returned leaseID is the only identity a transcript signature may bind to.
func (r *leaseRegistry) verifySigningAccessTokenLease(req *http.Request) (string, bool) {
	now := time.Now().UTC()
	claims, err := identity.VerifyLeaseAccessToken(req.Header.Get(types.HeaderAccessToken), r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return "", false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record, err := r.recordForVerifiedLease(claims.Identity.Key(), claims.LeaseID, now)
	if err != nil {
		return "", false
	}
	if !record.isPublicEntry() {
		return "", false
	}
	if !r.isRoutableLocked(record.Key()) {
		return "", false
	}
	return claims.LeaseID, true
}

func (r *leaseRegistry) Touch(key, clientIP string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record := r.recordByKey(key, now)
	if record == nil {
		return
	}
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()

	var expired []*leaseRecord
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record != nil && record.isExpired(now) {
			expired = append(expired, record)
			if record.stream != nil {
				r.bps.ResetIdentityLimiter(record.Key())
			}
			r.deleteRecord(i)
			continue
		}
		i++
	}
	// Drop stale pushed access results for identities with no lease: their
	// registration never completed or the lease is gone, and the next
	// registration re-pushes the relay's current decision first. Fresh
	// entries survive so an in-flight registration cannot lose its decision.
	for key, pushedAt := range r.blocked {
		if now.Sub(pushedAt) <= defaultRegisterChallengeTTL {
			continue
		}
		if r.recordByKey(key, now) == nil {
			delete(r.blocked, key)
		}
	}
	r.mu.Unlock()

	for _, record := range expired {
		record.Close()
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
		if record.stream != nil {
			identityKey := record.Key()
			if !r.isRoutableLocked(identityKey) {
				continue
			}
			since := time.Duration(0)
			if !record.LastSeenAt.IsZero() {
				since = max(now.Sub(record.LastSeenAt), 0)
			}
			if record.stream.ReadyCount() == 0 && since >= 3*time.Minute {
				continue
			}
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
		if record == nil || record.stream == nil || record.isExpired(now) {
			continue
		}
		clientIP := record.ClientIP
		identityKey := record.Key()
		leases = append(leases, types.PolicyLease{
			Lease:       r.publicLease(record),
			IdentityKey: identityKey,
			BPS:         r.bps.IdentityBPS(identityKey),
			ClientIP:    clientIP,
			ReportedIP:  record.ReportedIP,
		})
	}
	return leases
}

func (r *leaseRegistry) deleteRecord(i int) {
	if record := r.records[i]; record != nil {
		r.cache.Detach(record.cacheLease())
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
		TCPEnabled:        record.tcpPort != nil,
		Metadata:          record.Metadata.Copy(),
	}
	if record.tcpPort != nil {
		lease.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort.TCPPort())
	}
	if record.datagram != nil {
		lease.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.stream != nil {
		lease.Ready = record.stream.ReadyCount()
	}
	return lease
}
