package portal

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
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
	sniPort        int
	tokenAuthority identity.Authority
	tokenIssuer    string
	policy         *policy.Runtime
	udpPorts       *transport.PortAllocator
	tcpPorts       *transport.PortAllocator
	proxy          *proxy
	mu             sync.RWMutex
}

func newLeaseRegistry(udpEnabled, tcpPortEnabled bool, minPort, maxPort int, rootHostname string, sniPort int, tokenAuthority identity.Authority, tokenIssuer string, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*leaseRegistry, error) {
	if tokenAuthority == nil {
		return nil, errors.New("lease token authority is required")
	}
	tokenIdentity := tokenAuthority.Identity()
	if strings.TrimSpace(tokenIdentity.PublicKey) == "" {
		return nil, errors.New("lease token authority public key is required")
	}
	runtime, err := policy.NewRuntime(udpEnabled, tcpPortEnabled, trustProxyHeaders, rawTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &leaseRegistry{
		records:        make([]*leaseRecord, 0),
		rootHostname:   utils.NormalizeHostname(rootHostname),
		sniPort:        sniPort,
		tokenAuthority: tokenAuthority,
		tokenIssuer:    tokenIssuer,
		policy:         runtime,
		udpPorts:       transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		tcpPorts:       transport.NewPortAllocator(minPort, maxPort, defaultPortReservationGrace),
		proxy:          &proxy{},
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
	hostHash := utils.HostnameHash(host)
	for _, record := range r.records {
		if record == nil || !record.isPublicEntry() || record.isExpired(now) {
			continue
		}
		if record.HostnameHash != "" && record.HostnameHash == hostHash {
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

func (r *leaseRegistry) Register(req types.RegisterChallengeRequest, clientIP, reportedIP string) (*leaseRecord, types.RegisterResponse, error) {
	if r == nil {
		return nil, types.RegisterResponse{}, errFeatureUnavailable
	}
	leaseIdentity, err := identity.NormalizeIdentity(req.Identity)
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

	identityKey := leaseIdentity.Key()
	routeHostname := utils.NormalizeHostname(req.RouteHostname)
	hostnameHash := strings.TrimSpace(req.HostnameHash)
	echConfigList := bytes.Clone(req.ECHConfigList)
	if hostnameHash != "" && routeHostname == "" {
		return nil, types.RegisterResponse{}, errors.New("hostname hash requires route hostname")
	}
	if len(echConfigList) > 0 && routeHostname == "" {
		return nil, types.RegisterResponse{}, errors.New("ech config list requires route hostname")
	}
	publicHostname := ""
	if routeHostname != "" {
		routeLabel, routeBase, ok := strings.Cut(routeHostname, ".")
		normalizedRouteLabel, labelErr := utils.NormalizeDNSLabel(routeLabel)
		if !ok || labelErr != nil || normalizedRouteLabel != routeLabel || routeBase != r.rootHostname {
			return nil, types.RegisterResponse{}, errors.New("route hostname must be a child of relay root hostname")
		}

		publicHostname, err = utils.LeaseHostname(leaseIdentity.Name, r.rootHostname)
		if err != nil {
			return nil, types.RegisterResponse{}, err
		}
		expectedHostnameHash := utils.HostnameHash(publicHostname)
		if hostnameHash != "" && hostnameHash != expectedHostnameHash {
			return nil, types.RegisterResponse{}, errors.New("hostname hash does not match public hostname")
		}
		hostnameHash = expectedHostnameHash
	}
	if len(echConfigList) > 0 {
		echConfigList, err = keyless.NormalizeEncryptedClientHelloConfigList(echConfigList)
		if err != nil {
			return nil, types.RegisterResponse{}, err
		}
	}
	echDNSHostname := ""
	if len(echConfigList) > 0 {
		echDNSHostname = publicHostname
	}
	if req.UDPEnabled && !r.policy.IsUDPEnabled() {
		return nil, types.RegisterResponse{}, errUDPDisabled
	}
	if req.TCPEnabled {
		if !r.policy.IsTCPPortEnabled() {
			return nil, types.RegisterResponse{}, errTCPPortDisabled
		}
		if r.proxy == nil {
			return nil, types.RegisterResponse{}, errors.New("tcp proxy is not available")
		}
	}

	hostname := routeHostname
	if hostname == "" {
		hostname, err = utils.LeaseHostname(leaseIdentity.Name, r.rootHostname)
		if err != nil {
			return nil, types.RegisterResponse{}, err
		}
	}

	accessToken, claims, err := auth.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, leaseIdentity, ttl)
	if err != nil {
		return nil, types.RegisterResponse{}, err
	}
	issuedAt := claims.IssuedAt.Time().UTC()
	expiresAt := claims.Expiry.Time().UTC()

	stream := transport.NewRelayStream(identityKey, defaultIdleKeepalive, defaultReadyQueueLimit)
	record := &leaseRecord{
		Identity:       leaseIdentity,
		Hostname:       hostname,
		HostnameHash:   hostnameHash,
		ECHConfigList:  echConfigList,
		ECHDNSHostname: echDNSHostname,
		Metadata:       req.Metadata.Copy(),
		ExpiresAt:      expiresAt,
		FirstSeenAt:    issuedAt,
		LastSeenAt:     issuedAt,
		ClientIP:       clientIP,
		ReportedIP:     utils.SanitizeReportedIP(reportedIP),
		stream:         stream,
	}

	if req.UDPEnabled {
		if r.udpPorts == nil {
			return nil, types.RegisterResponse{}, errors.New("udp port allocation not available")
		}
		port, err := r.udpPorts.Allocate(leaseIdentity.Name)
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
		port, err := r.tcpPorts.Allocate(leaseIdentity.Name)
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
		if existing.isPublicEntry() && existingKey != identityKey && existing.routesOverlap(record) {
			r.mu.Unlock()
			record.Close()
			return nil, types.RegisterResponse{}, errHostnameConflict
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
		if existing == nil || existing.stream != nil || !existing.isPublicEntry() || existing.Key() != identityKey {
			continue
		}
		if existing.routesOverlap(record) {
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
		ExpiresAt:   record.ExpiresAt,
		AccessToken: accessToken,
		SNIPort:     r.sniPort,
		UDPEnabled:  record.datagram != nil,
		TCPEnabled:  record.tcpPort != nil,
	}
	if record.datagram != nil {
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
	claims, err := auth.VerifyLeaseAccessToken(token, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return nil, errUnauthorized
	}
	r.mu.RLock()
	record := r.recordByKey(claims.Identity.Key(), now)
	r.mu.RUnlock()
	if record == nil {
		return nil, errLeaseNotFound
	}
	if !r.policy.IsIdentityRoutable(record.Key()) {
		return nil, errLeaseRejected
	}
	if record.stream == nil || (requireDatagram && record.datagram == nil) {
		return nil, errTransportMismatch
	}
	return record, nil
}

func (r *leaseRegistry) Renew(req types.RenewRequest, clientIP string) (types.RenewResponse, error) {
	if r == nil {
		return types.RenewResponse{}, errFeatureUnavailable
	}
	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
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
	record.Metadata = req.Metadata.Copy()
	r.policy.IPFilter().RegisterIdentityIP(leaseKey, clientIP)
	recordIdentity := record.Identity
	r.mu.Unlock()

	nextAccessToken, _, err := auth.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, recordIdentity, ttl)
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
	claims, err := auth.VerifyLeaseAccessToken(req.AccessToken, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, time.Now().UTC())
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

func (r *leaseRegistry) promoteECHDNS(record *leaseRecord, manager *acme.Manager, sniPort int) {
	if !record.hasECHDNSRecord() {
		return
	}

	go func() {
		active := false
		now := time.Now()
		r.mu.RLock()
		for _, existing := range r.records {
			if existing == record && !existing.isExpired(now) {
				active = true
				break
			}
		}
		r.mu.RUnlock()
		if !active {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultClaimTimeout)
		err := record.syncECHDNS(ctx, manager, sniPort)
		cancel()

		if err != nil {
			log.Warn().
				Err(err).
				Str("hostname", record.ECHDNSHostname).
				Str("route_hostname", record.Hostname).
				Str("address", record.Address).
				Msg("promote ech dns record")
		}

		hostnameActive := false
		now = time.Now()
		r.mu.RLock()
		for _, existing := range r.records {
			if existing != nil && !existing.isExpired(now) && existing.hasECHDNSRecord() && existing.ECHDNSHostname == record.ECHDNSHostname {
				hostnameActive = true
				break
			}
		}
		r.mu.RUnlock()
		if !hostnameActive {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), defaultClaimTimeout)
			record.deleteECHDNS(cleanupCtx, manager)
			cleanupCancel()
		}
	}()
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri, clientIP string) (types.RegisterChallengeResponse, error) {
	if r == nil {
		return types.RegisterChallengeResponse{}, errFeatureUnavailable
	}
	if len(req.ECHConfigList) > 0 {
		echConfigList, err := keyless.NormalizeEncryptedClientHelloConfigList(req.ECHConfigList)
		if err != nil {
			return types.RegisterChallengeResponse{}, err
		}
		req.ECHConfigList = echConfigList
	}

	now := time.Now().UTC()
	challenge, err := auth.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
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

func (r *leaseRegistry) issueLeaseAccessToken(record *leaseRecord, now time.Time) (string, error) {
	token, _, err := auth.IssueLeaseAccessToken(r.tokenAuthority, r.tokenIssuer, record.Identity, record.ExpiresAt.Sub(now))
	return token, err
}

func (r *leaseRegistry) verifySigningAccessToken(token string) error {
	now := time.Now().UTC()
	claims, err := auth.VerifyLeaseAccessToken(token, r.tokenAuthority.Identity().PublicKey, r.tokenIssuer, now)
	if err != nil {
		return errUnauthorized
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, record := range r.records {
		if record == nil || record.isExpired(now) || record.Key() != claims.Identity.Key() {
			continue
		}
		if record.stream != nil && record.isPublicEntry() {
			if !r.policy.IsIdentityRoutable(record.Key()) {
				return errLeaseRejected
			}
			return nil
		}
	}
	return errUnauthorized
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
			if !r.policy.IsIdentityRoutable(identityKey) {
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
	name := record.Name
	hostname := record.Hostname
	if record.stream != nil && record.HostnameHash != "" {
		if publicHostname, err := utils.LeaseHostname(record.Name, r.rootHostname); err == nil && utils.HostnameHash(publicHostname) == record.HostnameHash {
			hostname = publicHostname
		}
	} else if record.HostnameHash != "" && record.Hostname != "" {
		label, _, _ := strings.Cut(record.Hostname, ".")
		name = label
	}
	lease := types.Lease{
		Name:        name,
		ExpiresAt:   record.ExpiresAt,
		FirstSeenAt: record.FirstSeenAt,
		LastSeenAt:  record.LastSeenAt,
		Hostname:    hostname,
		UDPEnabled:  record.datagram != nil,
		TCPEnabled:  record.tcpPort != nil,
		Metadata:    record.Metadata.Copy(),
	}
	if record.tcpPort != nil {
		lease.TCPAddr = fmt.Sprintf("%s:%d", record.Hostname, record.tcpPort.TCPPort())
	}
	if record.datagram != nil {
		lease.UDPAddr = fmt.Sprintf("%s:%d", record.Hostname, record.datagram.UDPPort())
	}
	if record.stream != nil {
		lease.Ready = record.stream.ReadyCount()
	}
	return lease
}
