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
	records []*leaseRecord
	policy  *policy.Runtime
	mu      sync.RWMutex
}

func newLeaseRegistry(udpEnabled, tcpPortEnabled bool, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*leaseRegistry, error) {
	runtime, err := policy.NewRuntime(udpEnabled, tcpPortEnabled, trustProxyHeaders, rawTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &leaseRegistry{
		records: make([]*leaseRecord, 0),
		policy:  runtime,
	}, nil
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := r.records
	for _, record := range out {
		if record != nil && record.stream != nil {
			r.policy.ForgetIdentity(record.Key())
		}
	}
	r.records = nil
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
		if record.Hostname == host {
			return record, true
		}
	}
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		if record.Hostname != host && utils.HostnameMatchesPattern(record.Hostname, host) {
			return record, true
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

func (r *leaseRegistry) recordByHopToken(token string, now time.Time) *leaseRecord {
	for _, record := range r.records {
		if record == nil || record.isExpired(now) {
			continue
		}
		if (record.isHopMiddle() || record.isHopExit()) && record.hopToken == token {
			return record
		}
	}
	return nil
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
	record.hopToken = strings.TrimSpace(record.hopToken)

	r.mu.Lock()

	now := time.Now()
	if record.isPublicEntry() {
		for _, existing := range r.records {
			if existing == nil || !existing.isPublicEntry() || existing.isExpired(now) {
				continue
			}
			if existing.Hostname == hostname && existing.Key() != key {
				r.mu.Unlock()
				return errHostnameConflict
			}
		}
	}
	if record.isHopExit() {
		if existing := r.recordByHopToken(record.hopToken, now); existing != nil && existing.Key() != key {
			r.mu.Unlock()
			return errors.New("hop token conflict")
		}
	}

	var replaced *leaseRecord
	replacedIndex := -1
	for i := 0; i < len(r.records); i++ {
		existing := r.records[i]
		if existing != nil && existing.stream == nil && existing.isPublicEntry() &&
			existing.Hostname == hostname && existing.Key() == key {
			r.deleteRecord(i)
			i--
		}
	}
	for i, existing := range r.records {
		if existing != nil && existing.stream != nil && existing.Key() == key {
			replaced = existing
			replacedIndex = i
			r.policy.ForgetIdentity(existing.Key())
			break
		}
	}
	record.Hostname = hostname
	if replacedIndex >= 0 {
		r.records[replacedIndex] = record
	} else {
		r.records = append(r.records, record)
	}
	r.policy.IPFilter().RegisterIdentityIP(key, record.ClientIP)
	r.mu.Unlock()

	if replaced != nil && replaced != record {
		replaced.Close()
	}
	return nil
}

func (r *leaseRegistry) Renew(key string, ttl time.Duration, clientIP string, reportedIPs utils.PublicIPs) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record := r.recordByKey(key, time.Time{})
	if record == nil {
		return nil, errLeaseNotFound
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	if reportedIPs.Any() {
		record.ReportedIP = reportedIPs.PreferredIP()
		record.ReportedIPv4 = reportedIPs.IPv4
		record.ReportedIPv6 = reportedIPs.IPv6
	}
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
	return record, nil
}

func (r *leaseRegistry) Unregister(key string) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key = strings.TrimSpace(key)
	for i, record := range r.records {
		if record == nil || record.stream == nil || record.Key() != key {
			continue
		}
		r.deleteRecord(i)
		r.policy.ForgetIdentity(key)
		return record, nil
	}
	return nil, errLeaseNotFound
}

func (r *leaseRegistry) RecordByKey(key string, now time.Time) (*leaseRecord, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record := r.recordByKey(key, now)
	if record == nil {
		return nil, false
	}
	return record, true
}

func (r *leaseRegistry) RecordByHopToken(token string, now time.Time) (*leaseRecord, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record := r.recordByHopToken(token, now)
	if record != nil {
		return record, true
	}
	return nil, false
}

func (r *leaseRegistry) RegisterHopRoute(route *types.HopRoute, now time.Time) (*leaseRecord, error) {
	if route == nil {
		return nil, errors.New("hop route is required")
	}
	ownerKey, err := utils.AddressFromCompressedPublicKeyHex(route.OwnerPublicKey)
	if err != nil {
		return nil, err
	}
	matchHostname := utils.NormalizeHostname(route.MatchHostname)
	matchToken := strings.TrimSpace(route.MatchToken)
	overlayIPv4, overlayErr := utils.DeriveWireGuardOverlayIPv4(route.ForwardRelay.WireGuardPublicKey)
	forwardToken := strings.TrimSpace(route.ForwardToken)
	expiresAt := route.ExpiresAt.UTC()

	switch {
	case r == nil:
		return nil, errFeatureUnavailable
	case !expiresAt.After(now):
		return nil, errors.New("route expiry must be in the future")
	case matchHostname == "" && matchToken == "":
		return nil, errors.New("hostname or token matcher is required")
	case matchHostname != "" && matchToken != "":
		return nil, errors.New("hostname and token matchers are mutually exclusive")
	case overlayErr != nil:
		return nil, fmt.Errorf("forward relay overlay ipv4: %w", overlayErr)
	case forwardToken == "":
		return nil, errors.New("forward token is required")
	}
	name := matchHostname
	if label, _, ok := strings.Cut(matchHostname, "."); ok {
		name = label
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	record := &leaseRecord{
		Identity: types.Identity{
			Name:    name,
			Address: ownerKey,
		},
		Hostname:           matchHostname,
		ExpiresAt:          expiresAt,
		hopToken:           matchToken,
		hopNextOverlayIPv4: overlayIPv4,
		hopNextToken:       forwardToken,
	}
	switch {
	case record.isPublicEntry():
		for _, existing := range r.records {
			if existing == nil || !existing.isPublicEntry() || existing.isExpired(now) {
				continue
			}
			if existing.Hostname != record.Hostname {
				continue
			}
			if existing.stream != nil || !strings.EqualFold(existing.Address, record.Address) {
				return nil, errHostnameConflict
			}
		}
		for i, existing := range r.records {
			if existing != nil && existing.stream == nil && existing.isPublicEntry() &&
				existing.Hostname == record.Hostname &&
				strings.EqualFold(existing.Address, record.Address) {
				r.records[i] = record
				return record, nil
			}
		}
		r.records = append(r.records, record)
		return record, nil
	case record.isHopMiddle():
		if existing := r.recordByHopToken(record.hopToken, now); existing != nil {
			if !existing.isHopMiddle() || !strings.EqualFold(existing.Address, record.Address) {
				return nil, errors.New("hop token conflict")
			}
		}
		for i, existing := range r.records {
			if existing != nil && existing.isHopMiddle() &&
				existing.hopToken == record.hopToken &&
				strings.EqualFold(existing.Address, record.Address) {
				r.records[i] = record
				return record, nil
			}
		}
		r.records = append(r.records, record)
		return record, nil
	default:
		return nil, errors.New("invalid hop route")
	}
}

func (r *leaseRegistry) DeleteHopRoute(route *types.HopRoute) *leaseRecord {
	if r == nil || route == nil {
		return nil
	}
	ownerKey, err := utils.AddressFromCompressedPublicKeyHex(route.OwnerPublicKey)
	if err != nil {
		return nil
	}
	hostname := utils.NormalizeHostname(route.MatchHostname)
	token := strings.TrimSpace(route.MatchToken)

	var deleted *leaseRecord
	r.mu.Lock()
	for i := 0; i < len(r.records); i++ {
		record := r.records[i]
		if record == nil || record.stream != nil {
			continue
		}
		deleteRecord := false
		if hostname != "" {
			deleteRecord = record.isPublicEntry() &&
				record.Hostname == hostname &&
				strings.EqualFold(record.Address, ownerKey)
		}
		if token != "" {
			deleteRecord = record.isHopMiddle() &&
				record.hopToken == token &&
				strings.EqualFold(record.Address, ownerKey)
		}
		if deleteRecord {
			deleted = record
			r.deleteRecord(i)
			break
		}
	}
	r.mu.Unlock()
	return deleted
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string) (types.RegisterChallengeResponse, error) {
	if strings.TrimSpace(req.HopToken) != "" && (req.UDPEnabled || req.TCPEnabled) {
		return types.RegisterChallengeResponse{}, errTransportMismatch
	}
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
	r.records = append(r.records, &leaseRecord{
		ExpiresAt:         challenge.ExpiresAt,
		registerChallenge: challenge,
	})
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

	for i, record := range r.records {
		if record == nil || record.registerChallenge == nil || record.registerChallenge.ChallengeID != challengeID {
			continue
		}
		challenge := record.registerChallenge
		if challenge.Expired(now) {
			r.deleteRecord(i)
			return nil, auth.ErrRegisterChallengeExpired
		}
		if err := challenge.Verify(req, now); err != nil {
			return nil, err
		}

		r.deleteRecord(i)
		return challenge, nil
	}
	return nil, auth.ErrRegisterChallengeNotFound
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
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	var expired []*leaseRecord
	for i := 0; i < len(r.records); {
		record := r.records[i]
		if record != nil && record.isExpired(now) {
			expired = append(expired, record)
			if record.stream != nil {
				r.policy.ForgetIdentity(record.Key())
			}
			r.deleteRecord(i)
			continue
		}
		i++
	}
	return expired
}

func (r *leaseRegistry) countDatagramLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range r.records {
		if record != nil && !record.isExpired(now) && record.datagram != nil {
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
	for _, record := range r.records {
		if record != nil && !record.isExpired(now) && record.tcpPort != nil {
			count++
		}
	}
	return count
}

func (r *leaseRegistry) PublicLeases(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	leases := make([]types.Lease, 0, len(r.records))
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		if record.stream != nil {
			identityKey := record.Key()
			if r.policy.IsIdentityBanned(identityKey) || r.policy.IsIdentityDenied(identityKey) || !r.policy.EffectiveApproval(identityKey) || record.Metadata.Hide {
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

func (r *leaseRegistry) AdminLeases(now time.Time) []types.AdminLease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	leases := make([]types.AdminLease, 0, len(r.records))
	for _, record := range r.records {
		if record == nil || record.stream == nil || record.isExpired(now) {
			continue
		}
		clientIP := record.ClientIP
		identityKey := record.Key()
		leases = append(leases, types.AdminLease{
			Lease:        r.publicLease(record),
			IdentityKey:  identityKey,
			Address:      record.Address,
			BPS:          r.policy.BPSManager().IdentityBPS(identityKey),
			ClientIP:     clientIP,
			ReportedIP:   record.ReportedIP,
			ReportedIPv4: record.ReportedIPv4,
			ReportedIPv6: record.ReportedIPv6,
			IsApproved:   r.policy.EffectiveApproval(identityKey),
			IsBanned:     r.policy.IsIdentityBanned(identityKey),
			IsDenied:     r.policy.IsIdentityDenied(identityKey),
			IsIPBanned:   r.policy.IPFilter().IsIPBanned(clientIP),
		})
	}
	return leases
}

func (r *leaseRegistry) deleteRecord(i int) {
	last := len(r.records) - 1
	r.records[i] = r.records[last]
	r.records[last] = nil
	r.records = r.records[:last]
}

func (r *leaseRegistry) publicLease(record *leaseRecord) types.Lease {
	lease := types.Lease{
		Name:        record.Name,
		ExpiresAt:   record.ExpiresAt,
		FirstSeenAt: record.FirstSeenAt,
		LastSeenAt:  record.LastSeenAt,
		Hostname:    record.Hostname,
		UDPEnabled:  record.datagram != nil,
		TCPEnabled:  record.tcpPort != nil,
		Metadata:    record.Metadata.Copy(),
	}
	if record.tcpPort != nil {
		lease.TCPAddr = fmt.Sprintf("%s:%d", record.Hostname, record.tcpPort.TCPPort())
	}
	if record.stream != nil {
		lease.Ready = record.stream.ReadyCount()
	} else if record.isPublicEntry() {
		_, _, hasNextHop := record.nextHop()
		if !hasNextHop {
			return lease
		}
		lease.Ready = 1
	}
	return lease
}

type leaseRecord struct {
	types.Identity
	ExpiresAt    time.Time
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	ClientIP     string
	ReportedIP   string
	ReportedIPv4 string
	ReportedIPv6 string
	Hostname     string
	Metadata     types.LeaseMetadata

	hopToken           string
	hopNextOverlayIPv4 string
	hopNextToken       string
	registerChallenge  *auth.RegisterChallenge

	datagram  *transport.RelayDatagram
	udpPorts  *transport.PortAllocator
	tcpPort   *transport.RelayTCPPort
	tcpPorts  *transport.PortAllocator
	stream    *transport.RelayStream
	startErr  error
	startOnce sync.Once
}

func (r *leaseRecord) isPublicEntry() bool {
	return r != nil && r.Hostname != "" && r.hopToken == ""
}

func (r *leaseRecord) isHopMiddle() bool {
	_, _, hasNextHop := r.nextHop()
	return r != nil && r.Hostname == "" && r.hopToken != "" && hasNextHop
}

func (r *leaseRecord) isHopExit() bool {
	_, _, hasNextHop := r.nextHop()
	return r != nil && r.Hostname != "" && r.hopToken != "" && !hasNextHop
}

func (r *leaseRecord) nextHop() (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	overlayIPv4 := r.hopNextOverlayIPv4
	forwardToken := r.hopNextToken
	return overlayIPv4, forwardToken, overlayIPv4 != "" || forwardToken != ""
}

func (r *leaseRecord) isExpired(now time.Time) bool {
	return r != nil && !now.IsZero() && !now.Before(r.ExpiresAt)
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
