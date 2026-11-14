package acme

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/cloudflare"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/embedded"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/gcloud"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/hetzner"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/njalla"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/route53"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/vultr"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	TypeEmbedded   = "embedded"
	TypeCloudflare = "cloudflare"
	TypeGCloud     = "gcloud"
	TypeHetzner    = "hetzner"
	TypeNjalla     = "njalla"
	TypeRoute53    = "route53"
	TypeVultr      = "vultr"
)

type dnsProvider interface {
	Name() string
	ChallengeProvider(ctx context.Context) (challenge.Provider, error)
	EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error
	EnsureAddressRecord(ctx context.Context, name, publicIP string) error
	DeleteAddressRecords(ctx context.Context, name string) error
	EnsureTXTRecord(ctx context.Context, name, value string) error
	DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error
	EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error)
}

func (m *Manager) syncDNS(ctx context.Context) ([]string, error) {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil, nil
	}
	_, _, manual, err := m.manualCertificateOverride()
	if err != nil {
		return nil, err
	}
	if manual && m.dns.Name() != TypeEmbedded {
		return nil, nil
	}
	publicIPs, err := utils.ResolvePublicIPs(ctx)
	if err != nil {
		if manual && m.dns.Name() == TypeEmbedded && ctx.Err() == nil {
			m.commandMu.Lock()
			m.pendingDNSAddress = true
			m.commandMu.Unlock()
			log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("defer embedded DNS address initialization until the next DNS retry; using manual certificate")
			return nil, nil
		}
		return nil, fmt.Errorf("detect public ip: %w", err)
	}
	if err := m.syncDNSEnsureAddressRecords(ctx, publicIPs); err != nil {
		return publicIPs, err
	}
	m.commandMu.Lock()
	m.pendingDNSAddress = false
	m.commandMu.Unlock()
	return publicIPs, nil
}

func (m *Manager) syncDNSEnsureAddressRecords(ctx context.Context, publicIPs []string) error {
	var syncErr error
	for _, publicIP := range publicIPs {
		if err := m.dns.EnsureAddressRecords(ctx, m.cfg.BaseDomain, publicIP); err != nil {
			syncErr = errors.Join(syncErr, err)
		}
	}
	return syncErr
}

// dnsChallengeProvider stops lego's context-free propagation loop at the next
// poll after cancellation. Keep issuance synchronous: releasing issuanceMu while
// lego is still using the DNS provider would allow overlapping orders/cleanup.
// Provider publication uses the order context and cleanup has a separate bounded
// lifetime. Lego's in-flight DNS lookups still use their own timeouts, so this is
// not a hard deadline for the entire order. See the TLS configuration docs.
type dnsChallengeProvider struct {
	challenge.Provider
	ctx context.Context
}

func (p dnsChallengeProvider) Timeout() (time.Duration, time.Duration) {
	timeout, interval := dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
	if provider, ok := p.Provider.(challenge.ProviderTimeout); ok {
		timeout, interval = provider.Timeout()
	}

	if interval <= 0 {
		interval = dns01.DefaultPollingInterval
	}
	return timeout, min(interval, 5*time.Second)
}

func (p dnsChallengeProvider) checkPropagation(_, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
	if err := p.ctx.Err(); err != nil {
		return true, err
	}
	ready, err := check(fqdn, value)
	if ctxErr := p.ctx.Err(); ctxErr != nil {
		return true, ctxErr
	}
	return ready, err
}
func newDNSProvider(providerType string, cfg Config) (dnsProvider, error) {
	switch providerType {
	case TypeEmbedded:
		return embedded.New(embedded.Config{
			BaseDomain: cfg.BaseDomain,
			ListenAddr: fmt.Sprintf(":%d", cfg.EmbeddedDNSPort),
			KeyPath:    filepath.Join(cfg.KeyDir, types.DNSSECKeyFileName),
		})
	case TypeCloudflare:
		return cloudflare.New(cfg.CloudflareToken), nil
	case TypeGCloud:
		return gcloud.New(gcloud.Config{
			ProjectID:   cfg.GCPProjectID,
			ManagedZone: cfg.GCPManagedZone,
		}), nil
	case TypeHetzner:
		return hetzner.New(cfg.HetznerAPIToken), nil
	case TypeNjalla:
		return njalla.New(cfg.NjallaToken), nil
	case TypeRoute53:
		return route53.New(route53.Config{
			AccessKeyID:     cfg.AWSAccessKeyID,
			SecretAccessKey: cfg.AWSSecretAccessKey,
			SessionToken:    cfg.AWSSessionToken,
			Region:          cfg.AWSRegion,
			HostedZoneID:    cfg.AWSHostedZoneID,
			KMSKeyARN:       cfg.AWSKMSKeyARN,
		}), nil
	case TypeVultr:
		return vultr.New(cfg.VultrAPIKey), nil
	default:
		return nil, fmt.Errorf("unsupported acme dns provider: %q", providerType)
	}
}
