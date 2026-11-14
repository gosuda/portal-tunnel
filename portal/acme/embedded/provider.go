package embedded

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errEmbeddedDNSBaseDomainRequired = errors.New("embedded dns base domain is required")
	errEmbeddedDNSProviderIsNil      = errors.New("embedded dns provider is nil")
	errTxtRecordValueIsRequired      = errors.New("txt record value is required")
	errTxtRecordMatchPrefixRequired  = errors.New("txt record match prefix is required")
	errRecordNameIsRequired          = errors.New("record name is required")
)

const (
	defaultListenAddr         = ":53"
	recordTTL          uint32 = 60
	listenStartTimeout        = 5 * time.Second
	soaRefresh         uint32 = 7200
	soaRetry           uint32 = 3600
	soaExpire          uint32 = 1209600
	selfCheckTimeout          = 10 * time.Second
)

// Config configures the embedded authoritative DNS server.
type Config struct {
	// BaseDomain is the delegated zone the relay serves, for example
	// portal.example.com.
	BaseDomain string
	// ListenAddr is the UDP/TCP listen address. Defaults to :53.
	ListenAddr string
	// KeyPath is the persistent CSK file. It is required; losing this file
	// requires replacing the DS at the parent before validation can resume.
	KeyPath string
}

// Provider is an authoritative-only DNS server for the relay zone plus the
// DNSProvider implementation used by the ACME manager.
type Provider struct {
	baseDomain string
	zone       string
	nsName     string
	listenAddr string

	mu     sync.RWMutex
	ipv4   net.IP
	ipv6   net.IP
	txt    map[string][]string
	serial uint32
	key    *dns.DNSKEY
	signer crypto.Signer
	signed *signedZone

	udpServer *dns.Server
	tcpServer *dns.Server
	ready     chan struct{}
	stopOnce  sync.Once
	stopErr   error

	started       bool
	selfCheckIPv4 sync.Once
	selfCheckIPv6 sync.Once
}

// New binds the UDP and TCP listeners and starts serving the zone before it
// returns.
func New(cfg Config) (*Provider, error) {
	baseDomain := utils.NormalizeBaseDomain(cfg.BaseDomain)
	if baseDomain == "" {
		return nil, errEmbeddedDNSBaseDomainRequired
	}
	if _, valid := dns.IsDomainName(dns.Fqdn(baseDomain)); !valid {
		return nil, fmt.Errorf("invalid embedded dns zone %q", baseDomain)
	}
	if net.ParseIP(baseDomain) != nil {
		return nil, fmt.Errorf("embedded dns base domain %q must be a hostname", baseDomain)
	}
	listenAddr := strings.TrimSpace(cfg.ListenAddr)
	listenAddr = cmp.Or(listenAddr, defaultListenAddr)
	p := &Provider{
		baseDomain: baseDomain,
		zone:       dns.Fqdn(baseDomain),
		nsName:     dns.Fqdn("ns." + baseDomain),
		txt:        make(map[string][]string),
		ready:      make(chan struct{}),
	}
	if err := p.initializeNewProviderSigning(cfg.KeyPath); err != nil {
		return nil, err
	}
	packetConn, listener, err := listenDNS(listenAddr)
	if err != nil {
		return nil, err
	}
	if err := p.serveNewProviderListeners(packetConn, listener, cfg.KeyPath); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) initializeNewProviderSigning(keyPath string) error {
	key, signer, err := loadSigningKey(keyPath, p.zone)
	if err != nil {
		return fmt.Errorf("initialize embedded dnssec: %w", err)
	}
	p.key = key
	p.signer = signer
	p.bumpSerialLocked()
	if _, err := p.signedZone(time.Now()); err != nil {
		return fmt.Errorf("sign embedded dns zone: %w", err)
	}
	return nil
}

func (p *Provider) serveNewProviderListeners(packetConn net.PacketConn, listener net.Listener, keyPath string) error {
	p.listenAddr = listener.Addr().String()
	var startMu sync.Mutex
	startedCount := 0
	notifyStarted := func() {
		startMu.Lock()
		defer startMu.Unlock()
		startedCount++
		if startedCount == 2 {
			close(p.ready)
		}
	}
	p.udpServer = &dns.Server{PacketConn: packetConn, Handler: p, NotifyStartedFunc: notifyStarted}
	p.tcpServer = &dns.Server{Listener: listener, Handler: p, NotifyStartedFunc: notifyStarted}
	go func() { _ = p.udpServer.ActivateAndServe() }()
	go func() { _ = p.tcpServer.ActivateAndServe() }()
	select {
	case <-p.ready:
	case <-time.After(listenStartTimeout):
		_ = p.Stop()
		return fmt.Errorf("embedded dns listeners on %s did not start within %s", p.listenAddr, listenStartTimeout)
	}
	p.started = true
	_, ds, message, _ := p.EnsureDNSSEC(context.Background(), p.baseDomain)
	log.Info().Str("ds_record", ds).Str("key_path", keyPath).Msg(message)
	log.Info().
		Str("listen_addr", p.listenAddr).
		Str("zone", p.zone).
		Str("nameserver", p.nsName).
		Msg("embedded authoritative dns server started")
	return nil
}

// Stop shuts down the authoritative listeners. It is safe to call multiple
// times.
func (p *Provider) Stop() error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		var errs []error
		if p.udpServer != nil {
			if err := p.udpServer.Shutdown(); err != nil {
				errs = append(errs, fmt.Errorf("stop embedded dns udp listener: %w", err))
			}
		}
		if p.tcpServer != nil {
			if err := p.tcpServer.Shutdown(); err != nil {
				errs = append(errs, fmt.Errorf("stop embedded dns tcp listener: %w", err))
			}
		}
		p.stopErr = errors.Join(errs...)
	})
	return p.stopErr
}

// Addr returns the resolved TCP listen address.
func (p *Provider) Addr() string { return p.listenAddr }

func (p *Provider) Name() string { return "embedded" }

// EnsureAddressRecords updates the supplied address family for the zone apex
// and every covered name. The other family's address remains unchanged.
func (p *Provider) EnsureAddressRecords(_ context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errEmbeddedDNSProviderIsNil
	}
	baseDomain, recordType, publicIP, err := dnsrecord.AddressRecordsInputs(baseDomain, publicIP)
	if err != nil {
		return err
	}
	if baseDomain != p.baseDomain {
		return fmt.Errorf("hostname %q is outside embedded dns zone %q", baseDomain, p.baseDomain)
	}
	ip := net.ParseIP(publicIP)

	p.mu.Lock()
	defer p.mu.Unlock()
	address := &p.ipv4
	selfCheck := &p.selfCheckIPv4
	if recordType == "AAAA" {
		address = &p.ipv6
		selfCheck = &p.selfCheckIPv6
	} else {
		ip = ip.To4()
	}
	if !(*address).Equal(ip) {
		*address = ip
		p.bumpSerialLocked()
	}
	if p.started {
		selfCheck.Do(func() {
			go p.verifyDelegatedPath(ip)
		})
	}
	return nil
}

// EnsureAddressRecord is a no-op: address answers are synthesized zone-wide
// from the relay's last discovered addresses rather than stored per hostname.
func (p *Provider) EnsureAddressRecord(_ context.Context, name, publicIP string) error {
	if p == nil {
		return errEmbeddedDNSProviderIsNil
	}
	if _, err := p.zoneHostname(name); err != nil {
		return err
	}
	_, _, _, err := dnsrecord.AddressRecordInputs(name, publicIP)
	return err
}

// DeleteAddressRecords is a no-op because address answers are synthesized, not stored.
func (p *Provider) DeleteAddressRecords(context.Context, string) error {
	if p == nil {
		return errEmbeddedDNSProviderIsNil
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(_ context.Context, name, value string) error {
	if p == nil {
		return errEmbeddedDNSProviderIsNil
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errTxtRecordValueIsRequired
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.txt[fqdn]
	if slices.Contains(values, value) {
		return nil
	}
	p.txt[fqdn] = append(values, value)
	p.bumpSerialLocked()
	return nil
}

func (p *Provider) DeleteTXTRecords(_ context.Context, name, matchPrefix string) error {
	if p == nil {
		return errEmbeddedDNSProviderIsNil
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errTxtRecordMatchPrefixRequired
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.txt[fqdn]
	remaining := slices.DeleteFunc(slices.Clone(values), func(value string) bool {
		return strings.HasPrefix(value, matchPrefix)
	})
	if len(remaining) == len(values) {
		return nil
	}
	if len(remaining) == 0 {
		delete(p.txt, fqdn)
	} else {
		p.txt[fqdn] = remaining
	}
	p.bumpSerialLocked()
	return nil
}

// EnsureDNSSEC exports the SHA-256 DS for the parent zone. Signing is active
// locally, but the state remains pending because parent-chain validation is
// not performed here. Local signing alone must not mark ENS as verified.
func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errEmbeddedDNSProviderIsNil
	}
	if utils.NormalizeBaseDomain(baseDomain) != p.baseDomain {
		return "", "", "", fmt.Errorf("domain %q is not embedded dns zone %q", baseDomain, p.baseDomain)
	}
	return "pending", p.key.ToDS(dns.SHA256).String(),
		"Publish this DS at the parent zone after NS/glue delegation is reachable; signing is active locally but Portal does not verify the parent DNSSEC chain, so ENS status remains unverified. Preserve the DNSSEC key file across restarts and migrations.", nil
}

func (p *Provider) zoneHostname(name string) (string, error) {
	name = utils.NormalizeHostname(name)
	if name == "" {
		return "", errRecordNameIsRequired
	}
	if _, valid := dns.IsDomainName(dns.Fqdn(name)); !valid {
		return "", fmt.Errorf("invalid dns record name %q", name)
	}
	if !utils.HostnameMatchesBaseDomain(name, p.baseDomain) {
		return "", fmt.Errorf("hostname %q is outside embedded dns zone %q", name, p.baseDomain)
	}
	return dns.Fqdn(name), nil
}

func (p *Provider) bumpSerialLocked() {
	if next := uint32(time.Now().Unix()); next > p.serial {
		p.serial = next
	} else {
		p.serial++
	}
}

func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	listenConfig := net.ListenConfig{}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse embedded dns listen address %q: %w", addr, err)
	}
	if portStr != "0" {
		return listenDNSFixedAddr(addr, listenConfig)
	}
	return listenDNSCompanionPort(addr, host, listenConfig)
}

func listenDNSFixedAddr(addr string, listenConfig net.ListenConfig) (net.PacketConn, net.Listener, error) {
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen embedded dns udp %s: %w", addr, err)
	}
	listener, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		_ = packetConn.Close()
		return nil, nil, fmt.Errorf("listen embedded dns tcp %s: %w", addr, err)
	}
	return packetConn, listener, nil
}

func listenDNSCompanionPort(addr, host string, listenConfig net.ListenConfig) (net.PacketConn, net.Listener, error) {
	var lastErr error
	for range 5 {
		packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("listen embedded dns udp %s: %w", addr, err)
		}
		port := packetConn.LocalAddr().(*net.UDPAddr).Port
		listener, err := listenConfig.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err == nil {
			return packetConn, listener, nil
		}
		lastErr = err
		_ = packetConn.Close()
	}
	return nil, nil, fmt.Errorf("listen embedded dns tcp companion port: %w", lastErr)
}

func (p *Provider) verifyDelegatedPath(ip net.IP) {
	label := make([]byte, 8)
	if _, err := rand.Read(label); err != nil {
		log.Warn().Err(err).Msg("dns self-check random label")
		return
	}
	name := hex.EncodeToString(label) + "." + p.zone
	ctx, cancel := context.WithTimeout(context.Background(), selfCheckTimeout)
	defer cancel()
	started := time.Now()
	network := "ip4"
	if ip.To4() == nil {
		network = "ip6"
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, network, name)
	elapsed := time.Since(started)
	if err != nil {
		log.Warn().Err(err).Str("name", name).Dur("elapsed", elapsed).Msg("dns self-check failed")
		return
	}
	if slices.ContainsFunc(addrs, func(addr net.IP) bool { return addr.Equal(ip) }) {
		log.Info().Str("name", name).Str("resolved", ip.String()).Dur("elapsed", elapsed).Msg("dns self-check passed")
		return
	}
	resolved := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		resolved = append(resolved, addr.String())
	}
	log.Warn().
		Str("name", name).
		Str("resolved", strings.Join(resolved, ",")).
		Str("expected", ip.String()).
		Dur("elapsed", elapsed).
		Msg("dns self-check resolved a different address")
}
func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errEmbeddedDNSProviderIsNil
	}
	return dnsrecord.NewChallengeProvider(ctx, dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval, p.presentTXT), nil
}

func (p *Provider) presentTXT(ctx context.Context, fqdn, value string) (dnsrecord.Cleanup, error) {
	name, err := p.zoneHostname(fqdn)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if slices.Contains(p.txt[name], value) {
		return nil, nil
	}
	p.txt[name] = append(p.txt[name], value)
	p.bumpSerialLocked()
	return func(ctx context.Context) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		values := p.txt[name]
		idx := slices.Index(values, value)
		if idx < 0 {
			return nil
		}
		values = slices.Delete(values, idx, idx+1)
		if len(values) == 0 {
			delete(p.txt, name)
		} else {
			p.txt[name] = values
		}
		p.bumpSerialLocked()
		return nil
	}, nil
}

// ServeDNS answers from one signed zone snapshot; it never performs recursion.
func (p *Provider) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	question := dns.Question{Name: ".", Qtype: dns.TypeNone}
	wildcard := false
	if len(r.Question) == 1 {
		question = r.Question[0]
	}
	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
	} else if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
	} else {
		wildcard = p.answerQuery(m, r, question)
	}
	p.writeResponse(w, r, m)
	event := log.Debug()
	if m.Rcode == dns.RcodeServerFailure {
		event = log.Warn()
	}
	event.
		Str("qname", question.Name).
		Str("qtype", dns.TypeToString[question.Qtype]).
		Str("rcode", dns.RcodeToString[m.Rcode]).
		Int("answers", len(m.Answer)).
		Bool("wildcard", wildcard).
		Str("remote", w.RemoteAddr().String()).
		Str("transport", w.LocalAddr().Network()).
		Msg("embedded dns query")
}

func (p *Provider) answerQuery(m *dns.Msg, r *dns.Msg, question dns.Question) bool {
	name := dns.CanonicalName(question.Name)
	if question.Qclass != dns.ClassINET || !dns.IsSubDomain(p.zone, name) {
		m.Rcode = dns.RcodeRefused
		return false
	}
	if question.Qtype == dns.TypeANY {
		m.Authoritative = true
		m.Rcode = dns.RcodeNotImplemented
		return false
	}
	z, err := p.signedZone(time.Now())
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		log.Error().Err(err).Msg("sign embedded dns zone")
		return false
	}
	m.Authoritative = true
	edns := r.IsEdns0()
	return p.answer(m, z, name, question.Qtype, edns != nil && edns.Do())
}

func (p *Provider) answer(m *dns.Msg, z *signedZone, name string, qtype uint16, do bool) bool {
	source, sets, exists, nextCloser := p.answerResolveSource(z, name)
	if exists {
		if qtype == dns.TypeRRSIG {
			answerRRSIGSets(m, sets, name)
		} else {
			m.Answer = appendRRSet(m.Answer, sets[qtype], name, do)
		}
	} else if len(z.records["*."+p.zone][dns.TypeA].records) != 0 || len(z.records["*."+p.zone][dns.TypeAAAA].records) != 0 {
		m.Rcode = dns.RcodeNameError
	} else {
		m.Rcode = dns.RcodeRefused
		return false
	}
	if len(m.Answer) == 0 {
		m.Ns = appendRRSet(m.Ns, z.records[p.zone][dns.TypeSOA], "", do)
	}
	if do {
		p.answerProofs(m, z, source, nextCloser)
	}
	if qtype == dns.TypeNS && name == p.zone {
		m.Extra = appendRRSet(m.Extra, z.records[p.nsName][dns.TypeA], "", do)
		m.Extra = appendRRSet(m.Extra, z.records[p.nsName][dns.TypeAAAA], "", do)
	}
	return exists && source != name
}

func (p *Provider) answerResolveSource(z *signedZone, name string) (string, map[uint16]signedRRSet, bool, string) {
	sets, exists := z.records[name]
	if exists {
		return name, sets, true, ""
	}
	closest := name
	var nextCloser string
	for z.records[closest] == nil {
		nextCloser = closest
		closest = parentName(closest)
	}
	source := "*." + closest
	sets, exists = z.records[source]
	return source, sets, exists, nextCloser
}

func answerRRSIGSets(m *dns.Msg, sets map[uint16]signedRRSet, name string) {
	types := slices.Collect(maps.Keys(sets))
	slices.Sort(types)
	for _, typ := range types {
		sig := dns.Copy(sets[typ].signature)
		sig.Header().Name = name
		m.Answer = append(m.Answer, sig)
	}
}

func (p *Provider) answerProofs(m *dns.Msg, z *signedZone, source, nextCloser string) {
	proofs := make(map[string]bool)
	addProof := func(set signedRRSet) {
		owner := set.records[0].Header().Name
		if !proofs[owner] {
			m.Ns = appendRRSet(m.Ns, set, "", true)
			proofs[owner] = true
		}
	}
	if nextCloser != "" {
		addProof(z.denial(nextCloser))
	}
	if len(m.Answer) == 0 {
		addProof(z.denial(source))
	}
}

func (p *Provider) writeResponse(w dns.ResponseWriter, query, m *dns.Msg) {
	size := dns.MaxMsgSize
	if strings.HasPrefix(w.LocalAddr().Network(), "udp") {
		size = udpResponseSize(query)
	}
	if edns := query.IsEdns0(); edns != nil {
		if edns.Version() != 0 {
			m.Rcode = dns.RcodeBadVers
			m.Answer, m.Ns, m.Extra = nil, nil, nil
		}
		m.SetEdns0(uint16(udpResponseSize(query)), edns.Do())
	}
	m.Truncate(size)
	if err := w.WriteMsg(m); err != nil {
		log.Debug().Err(err).Msg("write embedded dns response")
	}
}

func udpResponseSize(query *dns.Msg) int {
	size := dns.MinMsgSize
	if edns := query.IsEdns0(); edns != nil {
		if advertised := int(edns.UDPSize()); advertised > size {
			size = advertised
		}
	}
	return size
}

func (p *Provider) aRR(name string, ip net.IP) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: recordTTL},
		A:   append(net.IP(nil), ip...),
	}
}

func (p *Provider) aaaaRR(name string, ip net.IP) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: recordTTL},
		AAAA: append(net.IP(nil), ip...),
	}
}

func (p *Provider) nsRR() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: p.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:  p.nsName,
	}
}

func (p *Provider) soaRRLocked() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: p.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: recordTTL},
		Ns:      p.nsName,
		Mbox:    "hostmaster." + p.zone,
		Serial:  p.serial,
		Refresh: soaRefresh,
		Retry:   soaRetry,
		Expire:  soaExpire,
		Minttl:  recordTTL,
	}
}

func (p *Provider) txtRR(name, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: recordTTL},
		Txt: []string{value},
	}
}
