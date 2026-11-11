package acme

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/rs/zerolog/log"

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
