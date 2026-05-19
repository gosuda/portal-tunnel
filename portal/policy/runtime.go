package policy

import (
	"fmt"
	"net"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type PortPolicy struct {
	enabled   bool
	maxLeases int
}

func (p PortPolicy) IsEnabled() bool { return p.enabled }
func (p PortPolicy) MaxLeases() int  { return p.maxLeases }

func (p *PortPolicy) Set(enabled bool, maxLeases int) {
	p.enabled = enabled
	p.maxLeases = maxLeases
}

type runtimeConfig struct {
	udp               PortPolicy
	tcpPort           PortPolicy
	trustProxyHeaders bool
	trustedProxyCIDRs []*net.IPNet
}

func (cfg runtimeConfig) snapshot() runtimeConfig {
	cfg.trustedProxyCIDRs = utils.CloneSlice(cfg.trustedProxyCIDRs)
	return cfg
}

type Runtime struct {
	approver           *Approver
	bpsManager         *BPSManager
	ipFilter           *IPFilter
	config             *utils.Snapshot[runtimeConfig]
	bannedIdentityKeys *utils.Snapshot[map[string]struct{}]
}

func NewRuntime(udpEnabled, tcpPortEnabled bool, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*Runtime, error) {
	runtime := &Runtime{
		approver:   NewApprover(),
		bpsManager: NewBPSManager(),
		ipFilter:   NewIPFilter(),
		config: utils.NewSnapshot(runtimeConfig{
			udp:     PortPolicy{enabled: udpEnabled},
			tcpPort: PortPolicy{enabled: tcpPortEnabled},
		}, runtimeConfig.snapshot),
		bannedIdentityKeys: utils.NewSnapshot(map[string]struct{}{}, utils.CloneMap[string, struct{}]),
	}
	if err := runtime.SetProxyTrust(trustProxyHeaders, rawTrustedProxyCIDRs); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) Approver() *Approver {
	return r.approver
}

func (r *Runtime) IPFilter() *IPFilter {
	return r.ipFilter
}

func (r *Runtime) BPSManager() *BPSManager {
	return r.bpsManager
}

func (r *Runtime) BanIdentity(key string) {
	if r == nil || r.bannedIdentityKeys == nil || key == "" {
		return
	}
	r.bannedIdentityKeys.UpdateCopy(func(keys *map[string]struct{}) {
		if *keys == nil {
			*keys = make(map[string]struct{})
		}
		(*keys)[key] = struct{}{}
	})
}

func (r *Runtime) UnbanIdentity(key string) {
	if r == nil || r.bannedIdentityKeys == nil || key == "" {
		return
	}
	r.bannedIdentityKeys.UpdateCopy(func(keys *map[string]struct{}) {
		delete(*keys, key)
	})
}

func (r *Runtime) IsIdentityBanned(key string) bool {
	if r == nil || r.bannedIdentityKeys == nil || key == "" {
		return false
	}
	_, ok := r.bannedIdentityKeys.Load()[key]
	return ok
}

func (r *Runtime) BannedIdentityKeys() []string {
	if r == nil || r.bannedIdentityKeys == nil {
		return nil
	}
	keys := r.bannedIdentityKeys.Load()
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	return out
}

func (r *Runtime) SetBannedIdentityKeys(keys []string) {
	if r == nil || r.bannedIdentityKeys == nil {
		return
	}
	bannedIdentityKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		bannedIdentityKeys[key] = struct{}{}
	}

	r.bannedIdentityKeys.Store(bannedIdentityKeys)
}

func (r *Runtime) EffectiveApproval(key string) bool {
	if r.approver == nil || key == "" {
		return true
	}
	if r.approver.Mode() == ModeAuto {
		return true
	}
	return r.approver.IsApproved(key)
}

func (r *Runtime) IsIdentityDenied(key string) bool {
	if r.approver == nil || key == "" {
		return false
	}
	return r.approver.IsDenied(key)
}

func (r *Runtime) IsIdentityRoutable(key string) bool {
	if r.IsIdentityBanned(key) || r.IsIdentityDenied(key) {
		return false
	}
	return r.EffectiveApproval(key)
}

func (r *Runtime) SetUDPPolicy(enabled bool, maxLeases int) {
	if r == nil || r.config == nil {
		return
	}
	r.config.UpdateCopy(func(cfg *runtimeConfig) {
		cfg.udp.Set(enabled, maxLeases)
	})
}

func (r *Runtime) IsUDPEnabled() bool {
	if r == nil || r.config == nil {
		return false
	}
	return r.config.Load().udp.IsEnabled()
}

func (r *Runtime) UDPMaxLeases() int {
	if r == nil || r.config == nil {
		return 0
	}
	return r.config.Load().udp.MaxLeases()
}

func (r *Runtime) SetTCPPortPolicy(enabled bool, maxLeases int) {
	if r == nil || r.config == nil {
		return
	}
	r.config.UpdateCopy(func(cfg *runtimeConfig) {
		cfg.tcpPort.Set(enabled, maxLeases)
	})
}

func (r *Runtime) SetProxyTrust(trustProxyHeaders bool, rawTrustedProxyCIDRs string) error {
	if r == nil {
		return nil
	}
	trustedProxyCIDRs, err := utils.ParseCIDRs(rawTrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	if r.config == nil {
		r.config = utils.NewSnapshot(runtimeConfig{}, runtimeConfig.snapshot)
	}
	r.config.UpdateCopy(func(cfg *runtimeConfig) {
		cfg.trustProxyHeaders = trustProxyHeaders
		cfg.trustedProxyCIDRs = append([]*net.IPNet(nil), trustedProxyCIDRs...)
	})
	return nil
}

func (r *Runtime) IsTCPPortEnabled() bool {
	if r == nil || r.config == nil {
		return false
	}
	return r.config.Load().tcpPort.IsEnabled()
}

func (r *Runtime) TCPPortMaxLeases() int {
	if r == nil || r.config == nil {
		return 0
	}
	return r.config.Load().tcpPort.MaxLeases()
}

func (r *Runtime) ForgetIdentity(key string) {
	if r.ipFilter != nil {
		r.ipFilter.RemoveIdentityIP(key)
	}
	if r.bpsManager != nil {
		r.bpsManager.DeleteIdentityBPS(key)
	}
}
