// Package embedded serves the relay base domain from an authoritative DNS
// server running inside the relay process, removing the need for external
// DNS provider APIs. The relay becomes authoritative for its delegated
// namespace after a one-time NS delegation at the parent zone.
package embedded

import (
	"cmp"
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultListenAddr         = ":53"
	recordTTL          uint32 = 60
	listenStartTimeout        = 5 * time.Second
	soaRefresh         uint32 = 7200
	soaRetry           uint32 = 3600
	soaExpire          uint32 = 1209600
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
//
// A answers for the apex and every covered name are synthesized from the
// relay public IPv4, so they can never go stale. TXT records (ACME DNS-01
// and ENS gasless) and HTTPS records (ECH) are stored explicitly.
type Provider struct {
	baseDomain string
	zone       string
	nsName     string
	listenAddr string

	mu     sync.RWMutex
	ipv4   net.IP
	txt    map[string][]string
	https  map[string]httpsRecordValue
	serial uint32
	key    *dns.DNSKEY
	signer crypto.Signer
	signed *signedZone

	udpServer *dns.Server
	tcpServer *dns.Server
	ready     chan struct{}
	stopOnce  sync.Once
	stopErr   error
}

type httpsRecordValue struct {
	priority uint16
	value    []dns.SVCBKeyValue
}

// New binds the UDP and TCP listeners and starts serving the zone. Binding
// happens eagerly so DNS-01 TXT records are already served when the first
// certificate is issued.
func New(cfg Config) (*Provider, error) {
	baseDomain := utils.NormalizeBaseDomain(cfg.BaseDomain)
	if baseDomain == "" {
		return nil, errors.New("embedded dns base domain is required")
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
		https:      make(map[string]httpsRecordValue),
		ready:      make(chan struct{}),
	}

	var err error
	p.key, p.signer, err = loadSigningKey(cfg.KeyPath, p.zone)
	if err != nil {
		return nil, fmt.Errorf("initialize embedded dnssec: %w", err)
	}
	p.bumpSerialLocked()
	if _, err := p.signedZone(time.Now()); err != nil {
		return nil, fmt.Errorf("sign embedded dns zone: %w", err)
	}

	packetConn, listener, err := listenDNS(listenAddr)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("embedded dns listeners on %s did not start within %s", p.listenAddr, listenStartTimeout)
	}

	_, ds, message, _ := p.EnsureDNSSEC(context.Background(), p.baseDomain)
	log.Info().Str("ds_record", ds).Str("key_path", cfg.KeyPath).Msg(message)
	log.Info().
		Str("listen_addr", p.listenAddr).
		Str("zone", p.zone).
		Str("nameserver", p.nsName).
		Msg("embedded authoritative dns server started")
	return p, nil
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

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	return p, nil
}

func (p *Provider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name, err := p.zoneHostname(info.EffectiveFQDN)
	if err != nil {
		return err
	}
	return p.EnsureTXTRecord(context.Background(), name, info.Value)
}

func (p *Provider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	name, err := p.zoneHostname(info.EffectiveFQDN)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.txt[name]
	idx := slices.Index(values, info.Value)
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
}

// EnsureARecords records the relay public IPv4 used to synthesize A answers
// for the zone apex and every name it covers.
func (p *Provider) EnsureARecords(_ context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	if utils.NormalizeBaseDomain(baseDomain) != p.baseDomain {
		return fmt.Errorf("hostname %q is outside embedded dns zone %q", baseDomain, p.baseDomain)
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}
	ip := net.ParseIP(strings.TrimSpace(publicIPv4)).To4()

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ipv4.Equal(ip) {
		p.ipv4 = ip
		p.bumpSerialLocked()
	}
	return nil
}

// EnsureARecord is a no-op: A answers are synthesized zone-wide from the
// relay public IPv4, so explicit records cannot go stale.
func (p *Provider) EnsureARecord(_ context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	if _, err := p.zoneHostname(name); err != nil {
		return err
	}
	return utils.ValidateIPv4(publicIPv4)
}

// DeleteARecord is a no-op because A answers are synthesized, not stored.
func (p *Provider) DeleteARecord(context.Context, string) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(_ context.Context, name, value string) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
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
		return errors.New("embedded dns provider is nil")
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
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

func (p *Provider) EnsureHTTPSRecord(_ context.Context, name string, record dnsrecord.HTTPSRecord) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}
	record, err = record.Normalized()
	if err != nil {
		return err
	}
	value, err := parseSvcParams(record.SvcParams)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.https[fqdn] = httpsRecordValue{priority: record.Priority, value: value}
	p.bumpSerialLocked()
	return nil
}

func (p *Provider) DeleteHTTPSRecord(_ context.Context, name string) error {
	if p == nil {
		return errors.New("embedded dns provider is nil")
	}
	fqdn, err := p.zoneHostname(name)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.https[fqdn]; ok {
		delete(p.https, fqdn)
		p.bumpSerialLocked()
	}
	return nil
}

// EnsureDNSSEC exports the SHA-256 DS for the parent zone. Signing is active
// locally; this does not claim that the parent has published the DS.
func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("embedded dns provider is nil")
	}
	if utils.NormalizeBaseDomain(baseDomain) != p.baseDomain {
		return "", "", "", fmt.Errorf("domain %q is not embedded dns zone %q", baseDomain, p.baseDomain)
	}
	return "pending", p.key.ToDS(dns.SHA256).String(),
		"Publish this DS at the parent zone alongside the NS delegation; signing is active locally but parent DS publication is not verified. Preserve the DNSSEC key file across restarts and migrations.", nil
}

func (p *Provider) zoneHostname(name string) (string, error) {
	name = utils.NormalizeHostname(name)
	if name == "" {
		return "", errors.New("record name is required")
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

// listenDNS binds the UDP and TCP listeners. When the address requests an
// ephemeral port both transports are pinned to the same port.
func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	listenConfig := net.ListenConfig{}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse embedded dns listen address %q: %w", addr, err)
	}
	if portStr != "0" {
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
