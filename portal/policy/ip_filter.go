package policy

import (
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type IPFilter struct {
	bannedIPs      *utils.Snapshot[map[string]struct{}]
	identityToIP   map[string]string
	ipToIdentities map[string][]string
	mu             sync.RWMutex
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		bannedIPs:      utils.NewSnapshot(map[string]struct{}{}, utils.CloneMap[string, struct{}]),
		identityToIP:   make(map[string]string),
		ipToIdentities: make(map[string][]string),
	}
}

func (f *IPFilter) BanIP(ip string) {
	if f == nil || f.bannedIPs == nil {
		return
	}
	ip = canonicalBanIP(ip)
	f.bannedIPs.UpdateCopy(func(ips *map[string]struct{}) {
		if *ips == nil {
			*ips = make(map[string]struct{})
		}
		(*ips)[ip] = struct{}{}
	})
}

func (f *IPFilter) UnbanIP(ip string) {
	if f == nil || f.bannedIPs == nil {
		return
	}
	ip = canonicalBanIP(ip)
	f.bannedIPs.UpdateCopy(func(ips *map[string]struct{}) {
		delete(*ips, ip)
	})
}

func (f *IPFilter) IsIPBanned(ip string) bool {
	if f == nil || f.bannedIPs == nil {
		return false
	}
	_, ok := f.bannedIPs.Load()[canonicalBanIP(ip)]
	return ok
}

func (f *IPFilter) BannedIPs() []string {
	if f == nil || f.bannedIPs == nil {
		return nil
	}
	ips := f.bannedIPs.Load()
	out := make([]string, 0, len(ips))
	for ip := range ips {
		out = append(out, ip)
	}
	return out
}

func (f *IPFilter) SetBannedIPs(ips []string) {
	if f == nil || f.bannedIPs == nil {
		return
	}
	bannedIPs := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ip = canonicalBanIP(ip)
		if ip == "" {
			continue
		}
		bannedIPs[ip] = struct{}{}
	}
	f.bannedIPs.Store(bannedIPs)
}

func (f *IPFilter) RegisterIdentityIP(key, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if key == "" || ip == "" {
		return
	}
	ip = canonicalBanIP(ip)

	if oldIP, ok := f.identityToIP[key]; ok {
		if oldIP == ip {
			return
		}
		f.removeIdentityFromIPLocked(key, oldIP)
	}
	if slices.Contains(f.ipToIdentities[ip], key) {
		f.identityToIP[key] = ip
		return
	}

	f.identityToIP[key] = ip
	f.ipToIdentities[ip] = append(f.ipToIdentities[ip], key)
	if shared := len(f.ipToIdentities[ip]); shared > 1 {
		log.Warn().
			Str("client_ip", ip).
			Int("identities", shared).
			Msg("multiple identities share one client IP; if this relay is behind a proxy, configure TRUST_PROXY_HEADERS and TRUSTED_PROXY_CIDRs")
	}
}

func (f *IPFilter) IdentityIP(key string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if key == "" {
		return ""
	}
	return f.identityToIP[key]
}

func (f *IPFilter) RemoveIdentityIP(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if key == "" {
		return
	}
	ip, ok := f.identityToIP[key]
	if !ok {
		return
	}
	delete(f.identityToIP, key)
	f.removeIdentityFromIPLocked(key, ip)
}

func (f *IPFilter) removeIdentityFromIPLocked(key, ip string) {
	identities := f.ipToIdentities[ip]
	for i, candidate := range identities {
		if candidate == key {
			f.ipToIdentities[ip] = append(identities[:i], identities[i+1:]...)
			break
		}
	}
	if len(f.ipToIdentities[ip]) == 0 {
		delete(f.ipToIdentities, ip)
	}
}

// IdentitiesForIP reports how many distinct identities are currently
// attributed to one client IP. More than one behind a reverse proxy
// usually means the proxy trust boundary is not configured.
func (f *IPFilter) IdentitiesForIP(ip string) int {
	if f == nil {
		return 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ipToIdentities[canonicalBanIP(ip)])
}

// canonicalBanIP normalizes an address so the ban store, lookups, and
// unban all agree on one textual form: net.IP.String() renders
// IPv4-mapped addresses as dotted quads, so a "::ffff:1.2.3.4" entry and
// a "1.2.3.4" lookup can never diverge. Unparseable input is returned
// trimmed as-is.
func canonicalBanIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}
