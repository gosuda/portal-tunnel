package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	ensGaslessHostnamesFileName = "ens-gasless-hostnames.json"
	gaslessENSTXTPrefix         = "ENS1 "
	defaultENSGaslessResolver   = "0x238A8F792dFA6033814B18618aD4100654aeef01"
)

type ensDNSCommand struct {
	hostname string
	address  string
	remove   bool
}

func newENSStatus(cfg Config, dns DNSProvider) types.ENSStatus {
	provider := strings.TrimSpace(cfg.DNSProvider)
	if dns != nil {
		provider = dns.Name()
	}
	return types.ENSStatus{
		Enabled:  cfg.ENSGaslessEnabled && !utils.IsLocalRelayHost(cfg.BaseDomain),
		Provider: provider,
		Address:  strings.TrimSpace(cfg.ENSGaslessAddress),
	}
}

func (m *Manager) ENSStatus() types.ENSStatus {
	if m == nil {
		return types.ENSStatus{}
	}
	status := types.ENSStatus{}
	if m.ensStatus != nil {
		status = m.ensStatus.Load()
	}
	if status.Provider == "" && m.dns != nil {
		status.Provider = m.dns.Name()
	}
	return status
}

func (m *Manager) setENSStatus(state, record, message string, syncErr error) {
	if m == nil {
		return
	}
	status := newENSStatus(m.cfg, m.dns)
	status.DNSSECState = strings.TrimSpace(state)
	status.DSRecord = strings.TrimSpace(record)
	status.Message = strings.TrimSpace(message)
	status.Verified = syncErr == nil && ensDNSSECVerified(status.DNSSECState)
	if syncErr != nil {
		status.LastError = syncErr.Error()
	}

	if m.ensStatus == nil {
		m.ensStatus = utils.NewSnapshot(status)
		return
	}
	m.ensStatus.Store(status)
}

func ensDNSSECVerified(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "active", "on", "signing", "transfer":
		return true
	default:
		return false
	}
}

func (m *Manager) syncENSGasless(ctx context.Context) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	if err := m.syncENSDNSSEC(ctx); err != nil {
		return err
	}
	if err := m.applyENSCommand(ctx, ensDNSCommand{
		hostname: m.cfg.BaseDomain,
		address:  m.cfg.ENSGaslessAddress,
	}); err != nil {
		status := m.ENSStatus()
		m.setENSStatus(status.DNSSECState, status.DSRecord, status.Message, err)
		return fmt.Errorf("ensure ens gasless txt: %w", err)
	}
	return nil
}

func (m *Manager) syncENSDNSSEC(ctx context.Context) error {
	state, dsRecord, message, err := m.dns.EnsureDNSSEC(ctx, m.cfg.BaseDomain)
	if err != nil {
		m.setENSStatus("", "", "", err)
		return fmt.Errorf("ensure dnssec: %w", err)
	}
	m.setENSStatus(state, dsRecord, message, nil)
	return nil
}

func (m *Manager) SyncENSGaslessHostname(ctx context.Context, hostname, address string) error {
	if m == nil || !m.cfg.ENSGaslessEnabled || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return fmt.Errorf("hostname %q is outside acme base domain %q", hostname, m.cfg.BaseDomain)
	}

	address, err := identity.NormalizeEVMAddress(address)
	if err != nil {
		return fmt.Errorf("normalize ens gasless address: %w", err)
	}
	return m.queueENSCommand(ctx, ensDNSCommand{hostname: hostname, address: address})
}

func (m *Manager) DeleteENSGaslessHostname(ctx context.Context, hostname string) error {
	// Removal is deliberately not gated on ENSGaslessEnabled. Turning the feature
	// off must still converge the zone; gating the delete path orphans every
	// record the relay published, with no way back short of editing DNS by hand.
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return nil
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return nil
	}
	if hostname == m.cfg.BaseDomain {
		return nil
	}
	return m.queueENSCommand(ctx, ensDNSCommand{hostname: hostname, remove: true})
}

func (m *Manager) queueENSCommand(ctx context.Context, command ensDNSCommand) error {
	m.commandMu.RLock()
	defer m.commandMu.RUnlock()
	select {
	case <-m.stopCh:
		return errors.New("acme manager is stopped")
	default:
	}
	select {
	case m.ensCommands <- command:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) applyENSCommand(ctx context.Context, command ensDNSCommand) error {
	if command.remove {
		tracked, err := m.trackedENSGaslessHostnames()
		if err != nil {
			return err
		}
		if err := m.dns.DeleteTXTRecords(ctx, command.hostname, gaslessENSTXTPrefix); err != nil {
			return err
		}
		if publicIP := tracked[command.hostname]; publicIP != "" {
			if err := m.dns.DeleteARecordValue(ctx, command.hostname, publicIP); err != nil {
				return err
			}
		}
		return m.updateTrackedENSGaslessHostnames(func(hostnames map[string]string) {
			delete(hostnames, command.hostname)
		})
	}

	publicIP := ""
	if command.hostname != m.cfg.BaseDomain {
		var err error
		publicIP, err = utils.ResolvePublicIPv4(ctx)
		if err != nil {
			return fmt.Errorf("detect public ip: %w", err)
		}
		if err := m.dns.EnsureARecord(ctx, command.hostname, publicIP); err != nil {
			return fmt.Errorf("ensure ens gasless A record for %s: %w", command.hostname, err)
		}
		if err := m.updateTrackedENSGaslessHostnames(func(hostnames map[string]string) {
			hostnames[command.hostname] = publicIP
		}); err != nil {
			cleanupErr := m.dns.DeleteARecordValue(ctx, command.hostname, publicIP)
			return errors.Join(fmt.Errorf("track ens gasless A record for %s: %w", command.hostname, err), cleanupErr)
		}
	}
	value := gaslessENSTXTPrefix + defaultENSGaslessResolver + " " + strings.TrimSpace(command.address)
	if err := m.dns.ReplaceTXTRecords(ctx, command.hostname, gaslessENSTXTPrefix, value); err != nil {
		return err
	}
	return nil
}

func (m *Manager) reconcileTrackedENSGaslessHostnames(ctx context.Context) error {
	// Removal is deliberately not gated on ENSGaslessEnabled. Turning the feature
	// off must still converge the zone; gating the delete path orphans every
	// record the relay published, with no way back short of editing DNS by hand.
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	var cleanupErr error
	if err := m.updateTrackedENSGaslessHostnames(func(hostnames map[string]string) {
		for hostname, publicIP := range hostnames {
			if err := m.dns.DeleteTXTRecords(ctx, hostname, gaslessENSTXTPrefix); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless txt for %s: %w", hostname, err))
				continue
			}
			if publicIP != "" {
				if err := m.dns.DeleteARecordValue(ctx, hostname, publicIP); err != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless A record for %s: %w", hostname, err))
					continue
				}
			}
			delete(hostnames, hostname)
		}
	}); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("persist ens gasless hostnames: %w", err))
	}
	return cleanupErr
}

func (m *Manager) syncTrackedENSGaslessHostARecords(ctx context.Context, publicIP string) error {
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	var syncErr error
	updated := make(map[string]string)
	for hostname := range hostnames {
		if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("ensure ens gasless A record for %s: %w", hostname, err))
			continue
		}
		updated[hostname] = strings.TrimSpace(publicIP)
	}
	if len(updated) > 0 {
		if err := m.updateTrackedENSGaslessHostnames(func(hostnames map[string]string) {
			for hostname, managedIP := range updated {
				hostnames[hostname] = managedIP
			}
		}); err != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("persist ens gasless A records: %w", err))
		}
	}
	return syncErr
}

func (m *Manager) trackedENSGaslessHostnames() (map[string]string, error) {
	if m == nil {
		return nil, nil
	}

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil
	}
	if err != nil {
		return nil, err
	}

	tracked := make(map[string]string)
	if err := json.Unmarshal(raw, &tracked); err != nil {
		var legacy []string
		if legacyErr := json.Unmarshal(raw, &legacy); legacyErr != nil {
			return nil, err
		}
		for _, hostname := range utils.NormalizeChildHostnames(legacy, m.cfg.BaseDomain) {
			tracked[hostname] = ""
		}
	}
	normalized := make(map[string]string, len(tracked))
	for hostname, publicIP := range tracked {
		hostname = utils.NormalizeHostname(hostname)
		if hostname == "" || hostname == m.cfg.BaseDomain || !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
			continue
		}
		if utils.ValidateIPv4(publicIP) != nil {
			publicIP = ""
		}
		normalized[hostname] = strings.TrimSpace(publicIP)
	}
	return normalized, nil
}

func (m *Manager) updateTrackedENSGaslessHostnames(update func(map[string]string)) error {
	if m == nil {
		return nil
	}

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	if update != nil {
		update(hostnames)
	}
	if len(hostnames) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return utils.WriteJSONFile(path, hostnames, 0o600)
}
