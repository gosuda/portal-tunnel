package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultLeaseTTL                          = 30 * time.Second
	defaultRegisterChallengeTTL              = 2 * time.Minute
	defaultRegisterChallengeOutstandingPerIP = 32
	defaultPortReservationGrace              = 5 * time.Minute
	defaultIdleKeepalive                     = 15 * time.Second
	defaultReadyQueueLimit                   = 8
)

type leaseRegistry struct {
	records         []*leaseRecord
	rootHostname    string
	sniPort         int
	tokenPrivateKey string
	tokenPublicKey  string
	tokenKeyID      string
	tokenIssuer     string
	policy          *policy.Runtime
	udpPorts        *transport.PortAllocator
	tcpPorts        *transport.PortAllocator
	proxy           *proxy
	mu              sync.RWMutex
}

func newLeaseRegistry(udpEnabled, tcpPortEnabled bool, minPort, maxPort int, rootHostname string, sniPort int, tokenPrivateKey, tokenPublicKey, tokenKeyID, tokenIssuer string, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*leaseRegistry, error) {
	runtime, err := policy.NewRuntime(udpEnabled, tcpPortEnabled, trustProxyHeaders, rawTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &leaseRegistry{
		records:         make([]*leaseRecord, 0),
		rootHostname:    utils.NormalizeHostname(rootHostname),
		sniPort:         sniPort,
		tokenPrivateKey: tokenPrivateKey,
		tokenPublicKey:  tokenPublicKey,
		tokenKeyID:      tokenKeyID,
		tokenIssuer:     tokenIssuer,
		policy:          runtime,
		udpPorts:        transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		tcpPorts:        transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		proxy:           &proxy{},
	}, nil
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	out := r.records
	for _, record := range out {
		if record != nil && record.stream != nil {
			r.policy.ForgetIdentity(record.Key())
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

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, clientIP, reportedIP string) (*leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	identity, err := utils.NormalizeIdentity(req.Identity)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	if r.policy.IPFilter().IsIPBanned(clientIP) {
		return nil, types.RegisterResponse{}, errIPBanned
	}

	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	identityKey := identity.Key()
	hostname, err := utils.LeaseHostname(identity.Name, r.rootHostname)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	hopToken := strings.TrimSpace(req.HopToken)
	if hopToken != "" && (req.UDPEnabled || req.TCPEnabled) {
		return nil, types.RegisterResponse{}, errTransportMismatch
	}
	if req.UDPEnabled {
		if !r.policy.IsUDPEnabled() {
			return nil, types.RegisterResponse{}, errUDPDisabled
		}
	}
	if req.TCPEnabled {
		if !r.policy.IsTCPPortEnabled() {
			return nil, types.RegisterResponse{}, errTCPPortDisabled
		}
		if r.proxy == nil {
			return nil, types.RegisterResponse{}, errors.New("tcp proxy is not available")
		}
	}

	accessToken, claims, err := auth.IssueLeaseAccessToken(r.tokenPrivateKey, r.tokenKeyID, r.tokenIssuer, identity, ttl)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()

	stream := transport.NewRelayStream(identityKey, defaultIdleKeepalive, defaultReadyQueueLimit)
	record := &leaseRecord{
		Identity:    identity,
		Hostname:    hostname,
		Metadata:    req.Metadata,
		ExpiresAt:   expiresAt,
		FirstSeenAt: issuedAt,
		LastSeenAt:  issuedAt,
		ClientIP:    clientIP,
		ReportedIP:  utils.SanitizeReportedIP(reportedIP),
		hopToken:    hopToken,
		stream:      stream,
	}

	if req.UDPEnabled {
		if r.udpPorts == nil {
			return nil, types.RegisterResponse{}, errors.New("udp port allocation not available")
		}
		port, err := r.udpPorts.Allocate(identity.Name)
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
		port, err := r.tcpPorts.Allocate(identity.Name)
		if err != nil {
			record.Close()
			if errors.Is(err, transport.ErrPortExhausted) {
				return nil, types.RegisterResponse{}, errTCPPortExhausted
			}
			return nil, types.RegisterResponse{}, err
		}
		record.tcpPort = transport.NewRelayTCPPort(identityKey, port, stream, func(left, right net.Conn) {
			r.proxy.bridge(left, right, identityKey, r.policy.BPSManager())
		})
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
		if existing.isPublicEntry() && existing.Hostname == hostname && existingKey != identityKey {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errHostnameConflict
		}
		if hopToken != "" && (existing.isHopMiddle() || existing.isHopExit()) && existing.hopToken == hopToken && existingKey != identityKey {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errors.New("hop token conflict")
		}
	}
	if record.datagram != nil {
		if max := r.policy.UDPMaxLeases(); max > 0 && udpLeases >= max {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errUDPCapacityExceeded
		}
	}
	if record.tcpPort != nil {
		if max := r.policy.TCPPortMaxLeases(); max > 0 && tcpLeases >= max {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errTCPPortCapacityExceeded
		}
	}
	for i := 0; i < len(r.records); i++ {
		existing := r.records[i]
		if existing != nil && existing.stream == nil && existing.isPublicEntry() &&
			existing.Hostname == hostname && existing.Key() == identityKey {
			r.deleteRecord(i)
			i--
		}
	}
	if replacedIndex >= 0 {
		r.policy.ForgetIdentity(identityKey)
		r.records[replacedIndex] = record
	} else {
		r.records = append(r.records, record)
	}
	r.policy.IPFilter().RegisterIdentityIP(identityKey, record.ClientIP)
	r.mu.Unlock()

	if replaced != nil {
		replaced.Close()
	}

	resp := types.RegisterResponse{
		Identity:    record.Identity,
		Hostname:    record.Hostname,
		ExpiresAt:   record.ExpiresAt,
		AccessToken: accessToken,
		UDPEnabled:  record.datagram != nil,
		TCPEnabled:  record.tcpPort != nil,
	}
	if record.datagram != nil {
		resp.SNIPort = r.sniPort
		resp.UDPAddr = fmt.Sprintf("%s:%d", r.rootHostname, record.datagram.UDPPort())
	}
	if record.tcpPort != nil {
		resp.TCPAddr = fmt.Sprintf("%s:%d", r.rootHostname, record.tcpPort.TCPPort())
	}
	return record, resp, nil
}

func (r *leaseRegistry) admitLeaseByToken(token string, requireDatagram bool) (*leaseRecord, error) {
	if r == nil {
		return nil, errFeatureUnavailable
	}
	now := time.Now().UTC()
	claims, err := auth.VerifyLeaseAccessToken(token, r.tokenPublicKey, r.tokenIssuer, now)
	if err != nil {
		return nil, errUnauthorized
	}
	r.mu.RLock()
	lease := r.recordByKey(claims.Identity.Key(), now)
	r.mu.RUnlock()
	if lease == nil {
		return nil, errLeaseNotFound
	}
	if !r.policy.IsIdentityRoutable(lease.Key()) {
		return nil, errLeaseRejected
	}
	if lease.stream == nil || (requireDatagram && lease.datagram == nil) {
		return nil, errTransportMismatch
	}
	return lease, nil
}

func (r *leaseRegistry) Renew(req types.RenewRequest, clientIP string) (types.RenewResponse, error) {
	if r == nil {
		return types.RenewResponse{}, errFeatureUnavailable
	}
	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, r.tokenPublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return types.RenewResponse{}, errUnauthorized
	}
	ttl := defaultLeaseTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	leaseKey := claims.Identity.Key()
	reportedIP := utils.SanitizeReportedIP(req.ReportedIP)
	r.mu.Lock()
	record := r.recordByKey(leaseKey, time.Time{})
	if record == nil {
		r.mu.Unlock()
		return types.RenewResponse{}, errLeaseNotFound
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	if strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	r.policy.IPFilter().RegisterIdentityIP(leaseKey, clientIP)
	identity := record.Identity
	r.mu.Unlock()

	nextAccessToken, _, err := auth.IssueLeaseAccessToken(r.tokenPrivateKey, r.tokenKeyID, r.tokenIssuer, identity, ttl)
	if err != nil {
		return types.RenewResponse{}, &apiError{types.APIErrorCodeInternal, err.Error(), http.StatusInternalServerError}
	}

	return types.RenewResponse{
		ExpiresAt:   expiresAt,
		AccessToken: nextAccessToken,
	}, nil
}

func (r *leaseRegistry) Unregister(req types.UnregisterRequest) (*leaseRecord, error) {
	if r == nil {
		return nil, errFeatureUnavailable
	}
	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, r.tokenPublicKey, r.tokenIssuer, time.Now().UTC())
	if err != nil {
		return nil, errUnauthorized
	}
	r.mu.Lock()

	key := strings.TrimSpace(claims.Identity.Key())
	for i, record := range r.records {
		if record == nil || record.stream == nil || record.Key() != key {
			continue
		}
		r.deleteRecord(i)
		r.policy.ForgetIdentity(key)
		r.mu.Unlock()
		record.Close()
		return record, nil
	}
	r.mu.Unlock()
	return nil, errLeaseNotFound
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
		Metadata:           route.Metadata.Copy(),
		FirstSeenAt:        route.FirstSeenAt.UTC(),
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
	deleted.Close()
	return deleted
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri, clientIP string) (types.RegisterChallengeResponse, error) {
	if strings.TrimSpace(req.HopToken) != "" && (req.UDPEnabled || req.TCPEnabled) {
		return types.RegisterChallengeResponse{}, errTransportMismatch
	}
	if req.UDPEnabled {
		if !r.policy.IsUDPEnabled() {
			return types.RegisterChallengeResponse{}, errUDPDisabled
		}
	}
	if req.TCPEnabled {
		if !r.policy.IsTCPPortEnabled() {
			return types.RegisterChallengeResponse{}, errTCPPortDisabled
		}
	}

	now := time.Now().UTC()
	challenge, err := auth.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}
	clientIP = strings.ToLower(strings.TrimSpace(clientIP))
	if clientIP == "" {
		clientIP = "<unknown>"
	}

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
			if r.policy.IsIdentityBanned(identityKey) || r.policy.IsIdentityDenied(identityKey) || !r.policy.EffectiveApproval(identityKey) {
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
			Lease:       r.publicLease(record),
			IdentityKey: identityKey,
			Address:     record.Address,
			BPS:         r.policy.BPSManager().IdentityBPS(identityKey),
			ClientIP:    clientIP,
			ReportedIP:  record.ReportedIP,
			IsApproved:  r.policy.EffectiveApproval(identityKey),
			IsBanned:    r.policy.IsIdentityBanned(identityKey),
			IsDenied:    r.policy.IsIdentityDenied(identityKey),
			IsIPBanned:  r.policy.IPFilter().IsIPBanned(clientIP),
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
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ClientIP    string
	ReportedIP  string
	Hostname    string
	Metadata    types.LeaseMetadata

	hopToken           string
	hopNextOverlayIPv4 string
	hopNextToken       string
	registerChallenge  *auth.RegisterChallenge

	datagram *transport.RelayDatagram
	udpPorts *transport.PortAllocator
	tcpPort  *transport.RelayTCPPort
	tcpPorts *transport.PortAllocator
	stream   *transport.RelayStream
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
	if r.datagram != nil {
		if err := r.datagram.Start(context.Background()); err != nil {
			return err
		}
	}
	if r.tcpPort != nil {
		return r.tcpPort.Start(context.Background())
	}
	return nil
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
