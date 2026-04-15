package portal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultRegisterChallengeTTL = 2 * time.Minute

type leaseRegistry struct {
	routes             map[string]string
	leasesByKey        map[string]*leaseRecord
	registerChallenges map[string]*auth.RegisterChallenge
	policy             *policy.Runtime
	mu                 sync.RWMutex
}

func newLeaseRegistry(udpEnabled, tcpPortEnabled bool, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*leaseRegistry, error) {
	runtime, err := policy.NewRuntime(udpEnabled, tcpPortEnabled, trustProxyHeaders, rawTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &leaseRegistry{
		routes:             make(map[string]string),
		leasesByKey:        make(map[string]*leaseRecord),
		registerChallenges: make(map[string]*auth.RegisterChallenge),
		policy:             runtime,
	}, nil
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*leaseRecord, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		out = append(out, record)
		r.policy.ForgetIdentity(record.Key())
	}
	r.routes = make(map[string]string)
	r.leasesByKey = make(map[string]*leaseRecord)
	r.registerChallenges = make(map[string]*auth.RegisterChallenge)
	return out
}

func (r *leaseRegistry) Lookup(host string) (*leaseRecord, bool) {
	host = utils.NormalizeHostname(host)
	if host == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	key, ok := r.routes[host]
	if !ok {
		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			return nil, false
		}
		key, ok = r.routes["*."+strings.Join(parts[1:], ".")]
		if !ok {
			return nil, false
		}
	}
	record, ok := r.leasesByKey[key]
	return record, ok && record != nil
}

func (r *leaseRegistry) Register(record *leaseRecord) error {
	if record == nil {
		return errors.New("lease record is required")
	}

	key := record.Key()
	if key == "" {
		return errors.New("lease identity is required")
	}
	hostname := utils.NormalizeHostname(record.Hostname)
	if hostname == "" {
		return errors.New("lease hostname is required")
	}

	r.mu.Lock()

	if existingKey, ok := r.routes[hostname]; ok && existingKey != key {
		r.mu.Unlock()
		return errHostnameConflict
	}

	var replaced *leaseRecord
	if existing, ok := r.leasesByKey[key]; ok && existing != nil {
		replaced = existing
		delete(r.routes, utils.NormalizeHostname(existing.Hostname))
		r.policy.ForgetIdentity(existing.Key())
	}
	record.Hostname = hostname
	r.leasesByKey[key] = record
	r.routes[hostname] = key
	r.policy.IPFilter().RegisterIdentityIP(key, record.ClientIP)
	r.mu.Unlock()

	if replaced != nil && replaced != record {
		replaced.Close()
	}
	return nil
}

func (r *leaseRegistry) Renew(identity types.Identity, ttl time.Duration, clientIP, reportedIP string) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.leasesByKey[identity.Key()]
	if !ok {
		return nil, errLeaseNotFound
	}

	now := time.Now()
	record.ExpiresAt = now.Add(ttl)
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	if strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
	return record, nil
}

func (r *leaseRegistry) Unregister(identity types.Identity) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := identity.Key()
	record, ok := r.leasesByKey[key]
	if !ok {
		return nil, errLeaseNotFound
	}

	delete(r.leasesByKey, key)
	delete(r.routes, utils.NormalizeHostname(record.Hostname))
	r.policy.ForgetIdentity(key)
	return record, nil
}

func (r *leaseRegistry) Find(identity types.Identity) (*leaseRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	record, ok := r.leasesByKey[identity.Key()]
	if !ok || time.Now().After(record.ExpiresAt) {
		return nil, errLeaseNotFound
	}
	return record, nil
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string) (types.RegisterChallengeResponse, error) {
	if req.UDPEnabled {
		if !r.policy.IsUDPEnabled() {
			return types.RegisterChallengeResponse{}, errUDPDisabled
		}
		if max := r.policy.UDPMaxLeases(); max > 0 && r.countDatagramLeases() >= max {
			return types.RegisterChallengeResponse{}, errUDPCapacityExceeded
		}
	}
	if req.TCPEnabled {
		if !r.policy.IsTCPPortEnabled() {
			return types.RegisterChallengeResponse{}, errTCPPortDisabled
		}
		if max := r.policy.TCPPortMaxLeases(); max > 0 && r.countTCPPortLeases() >= max {
			return types.RegisterChallengeResponse{}, errTCPPortCapacityExceeded
		}
	}

	now := time.Now().UTC()
	challenge, err := auth.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}

	r.mu.Lock()
	r.registerChallenges[challenge.ChallengeID] = challenge
	r.mu.Unlock()

	return types.RegisterChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (r *leaseRegistry) consumeVerifiedRegisterChallenge(req types.RegisterRequest) (*auth.RegisterChallenge, error) {
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return nil, auth.ErrRegisterChallengeNotFound
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	challenge := r.registerChallenges[challengeID]
	if challenge == nil {
		return nil, auth.ErrRegisterChallengeNotFound
	}
	if challenge.Expired(now) {
		delete(r.registerChallenges, challengeID)
		return nil, auth.ErrRegisterChallengeExpired
	}
	if err := challenge.Verify(req, now); err != nil {
		return nil, err
	}

	delete(r.registerChallenges, challengeID)
	return challenge, nil
}

func (r *leaseRegistry) Touch(identity types.Identity, clientIP string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.leasesByKey[identity.Key()]
	if !ok {
		return
	}
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	expired := make([]*leaseRecord, 0)
	for key, record := range r.leasesByKey {
		if now.After(record.ExpiresAt) {
			expired = append(expired, record)
			delete(r.leasesByKey, key)
			delete(r.routes, utils.NormalizeHostname(record.Hostname))
			r.policy.ForgetIdentity(key)
		}
	}
	for challengeID, challenge := range r.registerChallenges {
		if challenge.Expired(now) {
			delete(r.registerChallenges, challengeID)
		}
	}
	return expired
}

func (r *leaseRegistry) countDatagramLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range r.leasesByKey {
		if now.Before(record.ExpiresAt) && record.datagram != nil {
			count++
		}
	}
	return count
}

func (r *leaseRegistry) countTCPPortLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range r.leasesByKey {
		if now.Before(record.ExpiresAt) && record.tcpPort != nil {
			count++
		}
	}
	return count
}

func (r *leaseRegistry) LeaseSnapshots(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]types.Lease, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		if record == nil || now.After(record.ExpiresAt) {
			continue
		}
		adminSnapshot := r.AdminSnapshot(record)
		since := time.Duration(0)
		if !adminSnapshot.LastSeenAt.IsZero() {
			since = max(now.Sub(adminSnapshot.LastSeenAt), 0)
		}
		if adminSnapshot.IsBanned || adminSnapshot.IsDenied || !adminSnapshot.IsApproved || adminSnapshot.Metadata.Hide {
			continue
		}
		if adminSnapshot.Ready == 0 && since >= 3*time.Minute {
			continue
		}
		snapshots = append(snapshots, adminSnapshot.Lease)
	}
	return snapshots
}

func (r *leaseRegistry) AdminLeaseSnapshots(now time.Time) []types.AdminLease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]types.AdminLease, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		if now.After(record.ExpiresAt) {
			continue
		}
		snapshots = append(snapshots, r.AdminSnapshot(record))
	}
	return snapshots
}

func (r *leaseRegistry) Snapshot(record *leaseRecord) types.Lease {
	snapshot := types.Lease{
		Name:        record.Name,
		ExpiresAt:   record.ExpiresAt,
		FirstSeenAt: record.FirstSeenAt,
		LastSeenAt:  record.LastSeenAt,
		Hostname:    record.Hostname,
		UDPEnabled:  record.UDPEnabled,
		TCPEnabled:  record.TCPEnabled,
		Metadata:    record.Metadata.Copy(),
	}
	if record.tcpPort != nil {
		snapshot.TCPAddr = fmt.Sprintf("%s:%d", record.Hostname, record.tcpPort.TCPPort())
	}
	if record.stream != nil {
		snapshot.Ready = record.stream.ReadyCount()
	}
	return snapshot
}

type leaseRecord struct {
	types.Identity
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ClientIP    string
	ReportedIP  string
	Hostname    string
	UDPEnabled  bool
	TCPEnabled  bool
	Metadata    types.LeaseMetadata
	datagram    *transport.RelayDatagram
	udpPorts    *transport.PortAllocator
	tcpPort     *transport.RelayTCPPort
	tcpPorts    *transport.PortAllocator
	stream      *transport.RelayStream
	startErr    error
	startOnce   sync.Once
}

func (r *leaseRegistry) AdminSnapshot(record *leaseRecord) types.AdminLease {
	clientIP := record.ClientIP
	identityKey := record.Key()
	return types.AdminLease{
		Lease:       r.Snapshot(record),
		IdentityKey: identityKey,
		Address:     record.Address,
		BPS:         r.policy.BPSManager().IdentityBPS(identityKey),
		ClientIP:    clientIP,
		ReportedIP:  record.ReportedIP,
		IsApproved:  r.policy.EffectiveApproval(identityKey),
		IsBanned:    r.policy.IsIdentityBanned(identityKey),
		IsDenied:    r.policy.IsIdentityDenied(identityKey),
		IsIPBanned:  r.policy.IPFilter().IsIPBanned(clientIP),
	}
}

func (r *leaseRecord) Start() error {
	r.startOnce.Do(func() {
		if r.datagram != nil {
			r.startErr = r.datagram.Start(context.Background())
			if r.startErr != nil {
				return
			}
		}
		if r.tcpPort != nil {
			r.startErr = r.tcpPort.Start(context.Background())
		}
	})
	return r.startErr
}

func (r *leaseRecord) Close() {
	if r == nil {
		return
	}
	if r.stream != nil {
		r.stream.Close()
	}
	if r.datagram != nil {
		port := r.datagram.UDPPort()
		r.datagram.Close()
		if port > 0 && r.udpPorts != nil {
			r.udpPorts.Release(port)
		}
	}
	if r.tcpPort != nil {
		port := r.tcpPort.TCPPort()
		r.tcpPort.Close()
		if port > 0 && r.tcpPorts != nil {
			r.tcpPorts.Release(port)
		}
	}
}
