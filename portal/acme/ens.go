package acme

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errHostnameIsRequired   = errors.New("hostname is required")
	errACMEManagerIsStopped = errors.New("acme manager is stopped")
	errLeaseDNSPending      = errors.New("lease address DNS is not ready for tenant issuance")
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
	ready    chan error
}

func newENSStatus(cfg Config, dns dnsProvider) types.ENSStatus {
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

// SyncLeaseHostname maintains exact canonical address records even without ENS.
// It shares the serialized DNS lifecycle and durable tracking used by ENS aliases.
func (m *Manager) SyncLeaseHostname(ctx context.Context, hostname, address string) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	if !m.cfg.ENSGaslessEnabled && !utils.IsLocalTLSHostname(hostname, m.cfg.BaseDomain) {
		return nil
	}
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errHostnameIsRequired
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

// isLeaseAddressParent recognizes the address-only legacy hostname directly
// under this relay root, not other legacy hostnames.
func (m *Manager) isLeaseAddressParent(hostname string) bool {
	label, _, found := strings.Cut(hostname, ".")
	if !found {
		return false
	}
	parent, err := utils.CanonicalLeaseHostname("", label, m.cfg.BaseDomain)
	return err == nil && parent == hostname
}

func (m *Manager) DeleteLeaseHostname(ctx context.Context, hostname string) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}

	hostname = utils.NormalizeHostname(hostname)
	if !m.cfg.ENSGaslessEnabled && !utils.IsLocalTLSHostname(hostname, m.cfg.BaseDomain) && !m.isLeaseAddressParent(hostname) {
		return nil
	}
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

// waitLeaseDNS gates external DNS-01 on the existing serialized address owner.
// The queued check follows registration's address command without writing DNS.
func (m *Manager) waitLeaseDNS(ctx context.Context, hostname string) error {
	if m.dns == nil || m.dns.Name() == TypeEmbedded {
		return nil
	}
	ready := make(chan error, 1)
	if err := m.queueENSCommand(ctx, ensDNSCommand{hostname: hostname, ready: ready}); err != nil {
		return err
	}
	select {
	case err := <-ready:
		return err
	case <-m.stopCh:
		return errACMEManagerIsStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) checkLeaseDNS(state *maintenanceLoopState, hostname string) error {
	_, parent, _ := strings.Cut(hostname, ".")
	// Tracking may precede failed writes; pending operations are not proof
	// that an address was published successfully.
	for _, name := range []string{hostname, parent} {
		if _, pending := state.pendingENS[name]; pending {
			return errLeaseDNSPending
		}
	}
	tracked, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	if !slices.Contains(tracked, hostname) || !slices.Contains(tracked, parent) {
		return errLeaseDNSPending
	}
	return nil
}

func (m *Manager) queueENSCommand(ctx context.Context, command ensDNSCommand) error {
	m.commandMu.RLock()
	defer m.commandMu.RUnlock()
	select {
	case <-m.stopCh:
		return errACMEManagerIsStopped
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
		return m.applyENSCommandRemove(ctx, command)
	}
	if command.hostname != m.cfg.BaseDomain {
		publicIPs, err := utils.ResolvePublicIPs(ctx)
		if err != nil {
			return fmt.Errorf("detect public ip: %w", err)
		}
		if utils.IsLocalTLSHostname(command.hostname, m.cfg.BaseDomain) {
			// An exact child suppresses wildcard answers for its address parent.
			// Publish the parent before the child to keep legacy URLs working.
			_, parent, _ := strings.Cut(command.hostname, ".")
			for _, name := range []string{parent, command.hostname} {
				// Track before DNS writes so a partial update can be withdrawn.
				if err := m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string { return append(hostnames, name) }); err != nil {
					return err
				}
				if err := m.ensureLeaseAddressRecords(ctx, name, publicIPs); err != nil {
					return err
				}
			}
		} else if err := m.ensureLeaseAddressRecords(ctx, command.hostname, publicIPs); err != nil {
			return err
		}
	}
	if !m.cfg.ENSGaslessEnabled {
		return nil
	}
	return m.applyENSCommandStoreGaslessTXT(ctx, command)
}

func (m *Manager) applyENSCommandRemove(ctx context.Context, command ensDNSCommand) error {
	if m.isLeaseAddressParent(command.hostname) {
		tracked, err := m.trackedENSGaslessHostnames()
		if err != nil {
			return err
		}
		if !slices.Contains(tracked, command.hostname) {
			return nil
		}
		for _, name := range tracked {
			if strings.HasSuffix(name, "."+command.hostname) && utils.IsLocalTLSHostname(name, m.cfg.BaseDomain) {
				return fmt.Errorf("wait for canonical DNS removal before withdrawing %s", command.hostname)
			}
		}
	}
	if err := m.dns.DeleteTXTRecords(ctx, command.hostname, gaslessENSTXTPrefix); err != nil {
		return err
	}
	if err := m.dns.DeleteAddressRecords(ctx, command.hostname); err != nil {
		return err
	}
	return m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		return slices.DeleteFunc(hostnames, func(hostname string) bool { return hostname == command.hostname })
	})
}

func (m *Manager) ensureLeaseAddressRecords(ctx context.Context, hostname string, publicIPs []string) error {
	var addressErr error
	for _, publicIP := range publicIPs {
		if err := m.dns.EnsureAddressRecord(ctx, hostname, publicIP); err != nil {
			addressErr = errors.Join(addressErr, err)
		}
	}
	if addressErr != nil {
		return fmt.Errorf("ensure lease address records for %s: %w", hostname, addressErr)
	}
	return nil
}

func (m *Manager) applyENSCommandStoreGaslessTXT(ctx context.Context, command ensDNSCommand) error {
	value := gaslessENSTXTPrefix + defaultENSGaslessResolver + " " + strings.TrimSpace(command.address)
	if err := m.dns.DeleteTXTRecords(ctx, command.hostname, gaslessENSTXTPrefix); err != nil {
		return err
	}
	if err := m.dns.EnsureTXTRecord(ctx, command.hostname, value); err != nil {
		return err
	}
	return m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		return append(hostnames, command.hostname)
	})
}
func (m *Manager) reconcileTrackedENSGaslessHostnames(ctx context.Context) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	var cleanupErr error
	if !m.cfg.ENSGaslessEnabled && strings.TrimSpace(m.cfg.ENSGaslessAddress) != "" {
		if err := m.dns.DeleteTXTRecords(ctx, m.cfg.BaseDomain, gaslessENSTXTPrefix); err != nil {
			cleanupErr = fmt.Errorf("delete ens gasless txt for %s: %w", m.cfg.BaseDomain, err)
		}
	}
	return m.withdrawTrackedENSHosts(ctx, cleanupErr)
}

func (m *Manager) withdrawTrackedENSHosts(ctx context.Context, cleanupErr error) error {
	if err := m.updateTrackedENSGaslessHostnames(func(hostnames []string) []string {
		// Withdraw address parents last. A failed child withdrawal must
		// leave its parent tracked and resolving across another restart.
		slices.SortStableFunc(hostnames, func(a, b string) int {
			return strings.Count(b, ".") - strings.Count(a, ".")
		})
		remaining := hostnames[:0]
		for _, hostname := range hostnames {
			if m.isLeaseAddressParent(hostname) && slices.ContainsFunc(remaining, func(name string) bool {
				return strings.HasSuffix(name, "."+hostname)
			}) {
				remaining = append(remaining, hostname)
				continue
			}
			if err := m.dns.DeleteTXTRecords(ctx, hostname, gaslessENSTXTPrefix); err != nil {
				remaining = append(remaining, hostname)
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless txt for %s: %w", hostname, err))
			} else if err := m.dns.DeleteAddressRecords(ctx, hostname); err != nil {
				remaining = append(remaining, hostname)
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete ens gasless address record for %s: %w", hostname, err))
			}
		}
		return remaining
	}); err != nil {
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("persist ens gasless hostnames: %w", err))
	}
	return cleanupErr
}

func (m *Manager) syncTrackedENSGaslessHostAddressRecords(ctx context.Context, publicIP string) error {
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	// Retry parent updates first, including after a partially completed command.
	slices.SortStableFunc(hostnames, func(a, b string) int {
		return strings.Count(a, ".") - strings.Count(b, ".")
	})
	var syncErr error
	failedParents := make(map[string]bool)
	for _, hostname := range hostnames {
		if utils.IsLocalTLSHostname(hostname, m.cfg.BaseDomain) {
			_, parent, _ := strings.Cut(hostname, ".")
			if failedParents[parent] {
				continue
			}
		}
		if err := m.dns.EnsureAddressRecord(ctx, hostname, publicIP); err != nil {
			if m.isLeaseAddressParent(hostname) {
				failedParents[hostname] = true
			}
			syncErr = errors.Join(syncErr, fmt.Errorf("ensure ens gasless address record for %s: %w", hostname, err))
		}
	}
	return syncErr
}

func (m *Manager) trackedENSGaslessHostnames() ([]string, error) {
	if m == nil {
		return nil, nil
	}

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	var hostnames []string
	if _, err := utils.ReadJSONFileIfExists(path, &hostnames); err != nil {
		return nil, err
	}
	return utils.NormalizeChildHostnames(hostnames, m.cfg.BaseDomain), nil
}

func (m *Manager) updateTrackedENSGaslessHostnames(update func([]string) []string) error {
	if m == nil {
		return nil
	}

	path := filepath.Join(m.cfg.KeyDir, ensGaslessHostnamesFileName)
	hostnames, err := m.trackedENSGaslessHostnames()
	if err != nil {
		return err
	}
	if update != nil {
		hostnames = utils.NormalizeChildHostnames(update(hostnames), m.cfg.BaseDomain)
	}
	if len(hostnames) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return utils.WriteJSONFile(path, hostnames, 0o600)
}
