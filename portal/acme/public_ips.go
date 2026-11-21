package acme

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errPublicIPNotAddress   = errors.New("is not an IP address")
	errPublicIPUnreachable  = errors.New("cannot be reached by clients")
	errPublicIPSecondFamily = errors.New("is a second address of its family; list at most one IPv4 and one IPv6 address")
)

// NormalizePublicIPs validates PUBLIC_IPS and returns it canonicalized, IPv4
// first. Each entry must be a bare IP address that clients can route to, with
// at most one per family, because the relay keeps one A and one AAAA record per
// name.
func NormalizePublicIPs(entries []string) ([]string, error) {
	var ipv4, ipv6 string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		canonical := utils.SanitizeReportedIP(entry)
		if canonical == "" {
			return nil, fmt.Errorf("PUBLIC_IPS: %q %w", entry, errPublicIPNotAddress)
		}
		ip := netip.MustParseAddr(canonical)
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return nil, fmt.Errorf("PUBLIC_IPS: %q %w: unspecified, loopback, link-local and multicast addresses are not allowed", entry, errPublicIPUnreachable)
		}
		family := &ipv6
		if ip.Is4() {
			family = &ipv4
		}
		if *family != "" {
			return nil, fmt.Errorf("PUBLIC_IPS: %q %w", entry, errPublicIPSecondFamily)
		}
		*family = canonical
	}
	var publicIPs []string
	for _, ip := range []string{ipv4, ipv6} {
		if ip != "" {
			publicIPs = append(publicIPs, ip)
		}
	}
	return publicIPs, nil
}

// publicIPs returns the addresses published in A and AAAA records: PUBLIC_IPS
// when it is set, for both families, otherwise the addresses discovered from
// outbound connections.
func (m *Manager) publicIPs(ctx context.Context) ([]string, error) {
	if len(m.cfg.PublicIPs) > 0 {
		return m.cfg.PublicIPs, nil
	}
	return utils.ResolvePublicIPs(ctx)
}

// warnPublicIPs reports a PUBLIC_IPS that has no effect because the relay
// manages no address records, and entries that only some clients can route to.
func (m *Manager) warnPublicIPs(manual bool) {
	if len(m.cfg.PublicIPs) == 0 {
		return
	}
	if types.IsLocalRelayHost(m.cfg.BaseDomain) || (manual && m.dns.Name() != TypeEmbedded && !m.cfg.ENSGaslessEnabled) {
		log.Warn().Strs("public_ips", m.cfg.PublicIPs).Str("base_domain", m.cfg.BaseDomain).Msg("PUBLIC_IPS has no effect: the relay manages no address records with these settings")
		return
	}
	for _, publicIP := range m.cfg.PublicIPs {
		if !utils.IsPublicIP(netip.MustParseAddr(publicIP)) {
			log.Warn().Str("public_ip", publicIP).Msg("PUBLIC_IPS entry is a private or special-use address; only clients that can route to it reach the relay")
		}
	}
}
