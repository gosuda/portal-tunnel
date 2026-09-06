package acme

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/cloudflare"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/embedded"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/gcloud"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/hetzner"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
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

type DNSProvider interface {
	Name() string
	ChallengeProvider(ctx context.Context) (challenge.Provider, error)
	EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error
	EnsureARecord(ctx context.Context, name, publicIPv4 string) error
	DeleteARecord(ctx context.Context, name string) error
	EnsureTXTRecord(ctx context.Context, name, value string) error
	DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error
	EnsureHTTPSRecord(ctx context.Context, name string, record dnsrecord.HTTPSRecord) error
	DeleteHTTPSRecord(ctx context.Context, name string) error
	EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error)
}

func NewDNSProvider(providerType string, cfg Config) (DNSProvider, error) {
	providerType = strings.ToLower(strings.TrimSpace(providerType))
	switch providerType {
	case TypeCloudflare, TypeGCloud, TypeHetzner, TypeNjalla, TypeRoute53, TypeVultr:
		log.Warn().Str("dns_provider", providerType).Msg("external managed DNS providers are deprecated and will be removed in a future major release; delegate the relay subdomain via NS to the embedded provider instead (no DNS API credentials required)")
	}
	switch providerType {
	case "", TypeEmbedded:
		keyDir := strings.TrimSpace(cfg.KeyDir)
		if keyDir == "" {
			return nil, errors.New("acme key directory is required")
		}
		return embedded.New(embedded.Config{
			BaseDomain: cfg.BaseDomain,
			ListenAddr: fmt.Sprintf(":%d", cfg.EmbeddedDNSPort),
			KeyPath:    filepath.Join(keyDir, types.DNSSECKeyFileName),
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

func (m *Manager) syncDNS(ctx context.Context) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	_, _, manual, err := m.manualCertificateOverride()
	if err != nil {
		return err
	}
	// Manual certificates bypass external A-record management, but the embedded
	// authoritative zone still needs its address before it can serve the relay.
	if manual && m.dns.Name() != TypeEmbedded {
		return nil
	}
	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip: %w", err)
	}
	return m.dns.EnsureARecords(ctx, m.cfg.BaseDomain, publicIP)
}
