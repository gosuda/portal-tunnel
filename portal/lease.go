package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/cache"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
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

func matchLookupHostnames(record *leaseRecord, host string) (bool, bool) {
	wildcard := false
	for _, hostname := range record.hostnames() {
		if hostname == host {
			return true, false
		}
		if !wildcard && utils.HostnameMatchesPattern(hostname, host) {
			wildcard = true
		}
	}
	return false, wildcard
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
		exact, wild := matchLookupHostnames(record, host)
		if exact {
			return record, true
		}
		if wildcard == nil && wild {
			wildcard = record
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
