package policy

import (
	"slices"
	"strings"
	"sync"

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
	ip = strings.TrimSpace(ip)
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
	ip = strings.TrimSpace(ip)
	f.bannedIPs.UpdateCopy(func(ips *map[string]struct{}) {
		delete(*ips, ip)
	})
}

func (f *IPFilter) IsIPBanned(ip string) bool {
	if f == nil || f.bannedIPs == nil {
		return false
	}
	_, ok := f.bannedIPs.Load()[strings.TrimSpace(ip)]
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
		ip = strings.TrimSpace(ip)
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
