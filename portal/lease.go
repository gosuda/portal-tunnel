package portal

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
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
	localTLS := namespace.IsLocalTLSHostname(host, r.rootHostname)
	var wildcard *leaseRecord
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		if localTLS {
			if record.Namespace == types.LocalTLSNamespaceV1 && record.CanonicalHostname == host {
				return record, true
			}
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

func (r *leaseRegistry) sweepRegisterChallengeLocked(now time.Time, sourceAddr netip.Addr) (int, int) {
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
	return pending, globalPending
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
	if _, _, err := r.resolveRegisterHostnames(challenge.Request.Identity, challenge.Request.Namespace); err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	pending, globalPending := r.sweepRegisterChallengeLocked(now, sourceAddr)
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

func (r *leaseRegistry) collectCleanupExpiredLocked(now time.Time) []*leaseRecord {
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
	return expired
}

func (r *leaseRegistry) pruneLifecycleBlockedLocked(now time.Time) {
	for key, blocked := range r.blocked {
		if now.Sub(blocked.pushedAt) <= defaultRegisterChallengeTTL {
			continue
		}
		if r.recordByKey(key, now) == nil {
			delete(r.blocked, key)
		}
	}
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()
	expired := r.collectCleanupExpiredLocked(now)
	r.pruneLifecycleBlockedLocked(now)
	r.mu.Unlock()

	for _, record := range expired {
		r.closeRecord(record)
	}
	return expired
}

func (r *leaseRegistry) includePublicLeaseLocked(record *leaseRecord, now time.Time) bool {
	if record == nil || !record.isPublicEntry() || record.isExpired(now) {
		return false
	}
	if record.Metadata.Hide {
		return false
	}
	if record.reverse == nil {
		return true
	}
	if !r.isRoutableLocked(record.ServiceKey()) {
		return false
	}
	since := time.Duration(0)
	if !record.LastSeenAt.IsZero() {
		since = max(now.Sub(record.LastSeenAt), 0)
	}
	if record.reverse.ReadyCount() == 0 && since >= 3*time.Minute {
		return false
	}
	return true
}

func (r *leaseRegistry) collectPublicLeasesLocked(now time.Time) []types.Lease {
	leases := make([]types.Lease, 0, len(r.records))
	for _, record := range r.records {
		if !r.includePublicLeaseLocked(record, now) {
			continue
		}
		leases = append(leases, r.publicLease(record, now))
	}
	return leases
}

func (r *leaseRegistry) PublicLeases(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collectPublicLeasesLocked(now)
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
			Lease:       r.publicLease(record, now),
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

func (r *leaseRegistry) publicLease(record *leaseRecord, now time.Time) types.Lease {
	lease := types.Lease{
		Namespace:               record.Namespace,
		LegacyCanonicalHostname: record.LegacyCanonicalHostname,
		Name:                    record.Name,
		Address:                 record.Address,
		ExpiresAt:               record.ExpiresAt,
		FirstSeenAt:             record.FirstSeenAt,
		LastSeenAt:              record.LastSeenAt,
		Hostname:                record.Hostname,
		CanonicalHostname:       record.CanonicalHostname,
		CanonicalReady:          record.Namespace == types.LocalTLSNamespaceV1 && now.Before(record.localTLSNotAfter) && now.Before(record.ExpiresAt),
		UDPEnabled:              record.datagram != nil,
		TCPEnabled:              record.tcpPort > 0,
		Metadata:                record.Metadata.Copy(),
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
	if len(held) >= r.unapprovedPerSource {
		if issued >= 0 {
			r.deleteRecord(issued)
		}
		return errUnapprovedLeaseLimit
	}
	return nil
}

func (r *leaseRegistry) resolveRegisterHostnames(leaseIdentity types.Identity, namespaceID string) (string, string, error) {
	var publicHostname string
	if leaseIdentity.Name != "" {
		var err error
		publicHostname, err = namespace.AliasHostname(leaseIdentity.Name, r.rootHostname)
		if err != nil {
			return "", "", err
		}
	}
	hostname := namespace.LegacyHostname
	switch namespaceID {
	case "":
	case types.LocalTLSNamespaceV1:
		hostname = namespace.LocalTLSHostname
	default:
		return "", "", fmt.Errorf("unsupported namespace %q", namespaceID)
	}
	canonicalHostname, err := hostname(leaseIdentity.Name, leaseIdentity.Address, r.rootHostname)
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

func (r *leaseRegistry) buildRegisterRecord(req types.RegisterChallengeRequest, sourceAddr netip.Addr, reportedIP string, served *acme.TLSMaterial) (*leaseRecord, string, error) {
	leaseIdentity := req.Identity
	if err := req.Metadata.Validate(); err != nil {
		return nil, "", err
	}
	ttl, err := requestedLeaseTTL(req.TTL)
	if err != nil {
		return nil, "", err
	}
	publicHostname, canonicalHostname, err := r.resolveRegisterHostnames(leaseIdentity, req.Namespace)
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
		Namespace:         req.Namespace,
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
	if req.Namespace == types.LocalTLSNamespaceV1 {
		record.LegacyCanonicalHostname, err = namespace.LegacyHostname(leaseIdentity.Name, leaseIdentity.Address, r.rootHostname)
		if err != nil {
			return nil, "", err
		}
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

func (r *leaseRegistry) checkRegisterCapacityLocked(record *leaseRecord, now time.Time) error {
	checkUDP := record.datagram != nil && r.udpMaxLeases > 0
	checkTCP := record.tcpPort > 0 && r.tcpMaxLeases > 0
	if !checkUDP && !checkTCP {
		return nil
	}
	identityKey := record.ServiceKey()
	udpLeases := 0
	tcpLeases := 0
	for _, existing := range r.records {
		if existing == nil || existing.isExpired(now) || existing.ServiceKey() == identityKey {
			continue
		}
		if existing.datagram != nil {
			udpLeases++
		}
		if existing.tcpPort > 0 {
			tcpLeases++
		}
	}
	if checkUDP && udpLeases >= r.udpMaxLeases {
		return errUDPCapacityExceeded
	}
	if checkTCP && tcpLeases >= r.tcpMaxLeases {
		return errTCPPortCapacityExceeded
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

func (r *leaseRegistry) checkRegisterHostnameLocked(record *leaseRecord, identityKey types.ServiceIdentityKey, req types.RegisterChallengeRequest, now time.Time) error {
	for _, existing := range r.records {
		if existing == nil || existing.isExpired(now) || existing.ServiceKey() == identityKey || !existing.isPublicEntry() {
			continue
		}
		if existing.CanonicalHostname == record.CanonicalHostname {
			return errHostnameConflict
		}
		if existing.Hostname != "" && existing.Hostname == record.Hostname {
			if !req.AllowCanonicalFallback && req.Namespace != types.LocalTLSNamespaceV1 {
				return errHostnameConflict
			}
			record.Hostname = ""
		}
	}
	return nil
}

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, sourceAddr netip.Addr, reportedIP string, self types.RelayDescriptor, descriptors []types.RelayDescriptor, served *acme.TLSMaterial) (*leaseRecord, *leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	record, accessToken, err := r.buildRegisterRecord(req, sourceAddr, reportedIP, served)
	if err != nil {
		return nil, nil, types.RegisterResponse{}, err
	}
	identityKey := record.ServiceKey()

	r.mu.Lock()
	if err := r.allocateRegisterTransportsLocked(record, req); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, nil, types.RegisterResponse{}, err
	}
	r.mu.Unlock()

	if err := record.Start(); err != nil {
		r.rollbackRecord(record)
		return nil, nil, types.RegisterResponse{}, err
	}

	r.mu.Lock()
	now := time.Now()
	replacedIndex := r.findRegisterReplacedLocked(identityKey)
	if err := r.checkRegisterHostnameLocked(record, identityKey, req, now); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, nil, types.RegisterResponse{}, err
	}
	if err := r.checkRegisterCapacityLocked(record, now); err != nil {
		r.mu.Unlock()
		r.rollbackRecord(record)
		return nil, nil, types.RegisterResponse{}, err
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
	var replaced *leaseRecord
	if replacedIndex < 0 {
		r.records = append(r.records, record)
	} else {
		replaced = r.records[replacedIndex]
		if !replaced.isExpired(now) && !replaced.FirstSeenAt.IsZero() && replaced.FirstSeenAt.Before(record.FirstSeenAt) {
			record.FirstSeenAt = replaced.FirstSeenAt
		}
		r.bps.ResetIdentityLimiter(record.ServiceKey())
		r.records[replacedIndex] = record
	}
	r.mu.Unlock()

	if replaced != nil {
		if r.overlay != nil {
			r.overlay.ForgetLease(replaced.id)
		}
		r.closeRecord(replaced)
	}

	reverseEndpoint, err := r.issueReverseEndpoint(reverseEndpointInput{
		leaseIdentity: record.Identity,
		leaseID:       record.id,
		expiresAt:     record.ExpiresAt,
		useOverlay:    record.Overlay,
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
			r.overlay.ForgetLease(record.id)
		}
		r.rollbackRecord(record)
		return nil, replaced, types.RegisterResponse{}, err
	}

	resp := types.RegisterResponse{
		Identity:                record.Identity,
		Namespace:               record.Namespace,
		LegacyCanonicalHostname: record.LegacyCanonicalHostname,
		Hostname:                record.Hostname,
		CanonicalHostname:       record.CanonicalHostname,
		ExpiresAt:               record.ExpiresAt,
		AccessToken:             accessToken,
		ReverseEndpoint:         reverseEndpoint,
		UDPEnabled:              record.datagram != nil,
		TCPEnabled:              record.tcpPort > 0,
	}
	if record.datagram != nil {
		resp.UDPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.datagram.UDPPort())
	}
	if record.tcpPort > 0 {
		resp.TCPAddr = fmt.Sprintf("%s:%d", record.CanonicalHostname, record.tcpPort)
	}
	return record, replaced, resp, nil
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

// tenantCertificateNames snapshots exact live ownership. A replacement lease
// must not complete an earlier owner's issuance request. Reassignable aliases
// are deliberately excluded from automatic certificate issuance.
func (r *leaseRegistry) tenantCertificateNames(record *leaseRecord) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, err := r.recordForVerifiedLeaseLocked(record.ServiceKey(), record.id, time.Now())
	if err != nil {
		return nil, err
	}
	if blocked, ok := r.blocked[current.ServiceKey()]; ok {
		return nil, blocked.refusal
	}
	if current.Namespace != types.LocalTLSNamespaceV1 || !namespace.IsLocalTLSHostname(current.CanonicalHostname, r.rootHostname) {
		return nil, errUnauthorized
	}
	if current.reverse == nil {
		return nil, errTransportMismatch
	}
	return []string{current.CanonicalHostname}, nil
}

// HandleTenantCertificate authenticates issuance with the existing lease token.
// The relay receives only a signed CSR and never handles the tenant private key.
func (s *Server) HandleTenantCertificate(w http.ResponseWriter, r *http.Request, approved []types.ServiceIdentityKey) {
	if !utils.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if !s.config().TenantCertificates || !s.acmeManager.TenantIssuanceConfigured() {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeTenantIssuanceDisabled, "automatic tenant certificate issuance is disabled on this relay")
		return
	}
	record, err := s.registry.admitLeaseByToken(r.Header.Get(types.HeaderAccessToken), false)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	names, err := s.registry.tenantCertificateNames(record)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	// Free registration is not a public CA issuance grant. Local development
	// certificates consume no public quota and retain automatic issuance.
	if !utils.IsLocalRelayHost(s.identity.Name) && !slices.Contains(approved, record.ServiceKey()) {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeTenantIssuanceNotApproved, "this service is not approved for automatic tenant certificate issuance")
		return
	}
	request, ok := utils.DecodeJSONRequest[types.TenantCertificateRequest](w, r, 16<<10)
	if !ok {
		return
	}
	csr, err := acme.ParseTenantCSR(request.CSRPEM, names)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	cert, err := s.acmeManager.ObtainTenantCertificate(r.Context(), csr)
	if err != nil {
		if errors.Is(err, acme.ErrTenantIssuanceDisabled) {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeTenantIssuanceDisabled, err.Error())
			return
		}
		if errors.Is(err, acme.ErrTenantOrderLimited) || errors.Is(err, acme.ErrTenantIssuerBusy) {
			w.Header().Set("Retry-After", "10")
			if errors.Is(err, acme.ErrTenantOrderLimited) {
				w.Header().Set("Retry-After", "3600")
			}
			utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, err.Error())
			return
		}
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, err.Error())
		return
	}
	names, err = s.registry.tenantCertificateNames(record)
	if err != nil {
		writeAPIErrorResponse(w, err)
		return
	}
	if !tenantCSRStillOwned(csr, names) {
		writeAPIErrorResponse(w, errUnauthorized)
		return
	}
	utils.WriteAPIData(w, http.StatusOK, types.TenantCertificateResponse{CertificatePEM: string(cert)})
}

func tenantCSRStillOwned(csr *x509.CertificateRequest, names []string) bool {
	for _, name := range csr.DNSNames {
		if !slices.Contains(names, name) {
			return false
		}
	}
	return true
}
