package acme

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type echDNSCommand struct {
	hostname string
	record   dnsrecord.HTTPSRecord
	remove   bool
}

func (m *Manager) SyncECHConfig(ctx context.Context, hostname string, echConfigList []byte, port int) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return nil
	}
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return fmt.Errorf("hostname %q is outside acme base domain %q", hostname, m.cfg.BaseDomain)
	}
	echConfigList, err := keyless.NormalizeEncryptedClientHelloConfigList(echConfigList)
	if err != nil {
		return err
	}
	if port < 0 || port > 65535 {
		return errors.New("https record port must be between 0 and 65535")
	}
	svcParams := `ech="` + base64.StdEncoding.EncodeToString(echConfigList) + `"`
	if port > 0 && port != 443 {
		svcParams += " port=" + strconv.Itoa(port)
	}
	record := dnsrecord.HTTPSRecord{Priority: 1, Target: ".", SvcParams: svcParams}
	record, err = record.Normalized()
	if err != nil {
		return err
	}
	return m.queueECHCommand(ctx, echDNSCommand{hostname: hostname, record: record})
}

func (m *Manager) DeleteECHConfig(ctx context.Context, hostname string) error {
	if m == nil || utils.IsLocalRelayHost(m.cfg.BaseDomain) {
		return nil
	}
	if m.dns == nil {
		return nil
	}
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return nil
	}
	if !utils.HostnameMatchesBaseDomain(hostname, m.cfg.BaseDomain) {
		return nil
	}

	return m.queueECHCommand(ctx, echDNSCommand{hostname: hostname, remove: true})
}

func (m *Manager) queueECHCommand(ctx context.Context, command echDNSCommand) error {
	m.commandMu.RLock()
	defer m.commandMu.RUnlock()
	select {
	case <-m.stopCh:
		return errors.New("acme manager is stopped")
	default:
	}
	select {
	case m.echCommands <- command:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) applyECHCommand(ctx context.Context, command echDNSCommand) error {
	if command.remove {
		if err := m.dns.DeleteHTTPSRecord(ctx, command.hostname); err != nil {
			return err
		}
		if command.hostname != m.cfg.BaseDomain {
			if err := m.dns.DeleteARecord(ctx, command.hostname); err != nil {
				return fmt.Errorf("delete ECH A record for %s: %w", command.hostname, err)
			}
		}
		return nil
	}

	publicIP, err := utils.ResolvePublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("detect public ip for ECH hostname %s: %w", command.hostname, err)
	}
	if err := m.dns.EnsureARecord(ctx, command.hostname, publicIP); err != nil {
		return fmt.Errorf("ensure ECH A record for %s: %w", command.hostname, err)
	}
	return m.dns.EnsureHTTPSRecord(ctx, command.hostname, command.record)
}
