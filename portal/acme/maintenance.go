package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultRenewInterval          = 24 * time.Hour
	defaultManagedDNSSyncInterval = 3 * time.Hour
	defaultDNSRetryInterval       = 10 * time.Minute
	defaultSyncTimeout            = 2 * time.Minute
)

func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()
	pendingECH := make(map[string]echDNSCommand)
	pendingENS := make(map[string]ensDNSCommand)
	activeECHARecords := make(map[string]struct{})
	trackECHARecord := func(command echDNSCommand) {
		if command.remove {
			delete(activeECHARecords, command.hostname)
			return
		}
		activeECHARecords[command.hostname] = struct{}{}
	}
	lastPublicIP := ""
	syncChangedARecords := func(ctx context.Context) error {
		if len(activeECHARecords) == 0 && !m.cfg.ENSGaslessEnabled {
			return nil
		}

		publicIP, err := utils.ResolvePublicIPv4(ctx)
		if err != nil {
			return fmt.Errorf("detect public ip: %w", err)
		}
		if publicIP == lastPublicIP {
			return nil
		}

		var syncErr error
		for hostname := range activeECHARecords {
			if err := m.dns.EnsureARecord(ctx, hostname, publicIP); err != nil {
				syncErr = errors.Join(syncErr, fmt.Errorf("ensure ECH A record for %s: %w", hostname, err))
			}
		}
		if m.cfg.ENSGaslessEnabled {
			syncErr = errors.Join(syncErr, m.syncTrackedENSGaslessHostARecords(ctx, publicIP))
		}
		if syncErr != nil {
			return syncErr
		}

		lastPublicIP = publicIP
		return nil
	}
	flushCommands := func(ctx context.Context) error {
	drainECH:
		for {
			select {
			case command := <-m.echCommands:
				trackECHARecord(command)
				pendingECH[command.hostname] = command
			default:
				break drainECH
			}
		}
	drainENS:
		for {
			select {
			case command := <-m.ensCommands:
				pendingENS[command.hostname] = command
			default:
				break drainENS
			}
		}

		var err error
		for hostname, command := range pendingECH {
			if commandErr := m.applyECHCommand(ctx, command); commandErr != nil {
				err = errors.Join(err, commandErr)
			} else {
				delete(pendingECH, hostname)
			}
		}
		for hostname, command := range pendingENS {
			if commandErr := m.applyENSCommand(ctx, command); commandErr != nil {
				err = errors.Join(err, commandErr)
			} else {
				delete(pendingENS, hostname)
			}
		}
		return err
	}

	renewTicker := time.NewTicker(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultManagedDNSSyncInterval)
	retryTicker := time.NewTicker(defaultDNSRetryInterval)
	defer renewTicker.Stop()
	defer dnsTicker.Stop()
	defer retryTicker.Stop()

	for {
		select {
		case <-m.stopCh:
			syncCtx, cancel := context.WithTimeout(m.stopCtx, defaultSyncTimeout)
			m.stopErr = flushCommands(syncCtx)
			cancel()
			if m.stopErr != nil {
				log.Warn().Err(m.stopErr).Str("base_domain", m.cfg.BaseDomain).Msg("flush dns records")
			}
			return
		case command := <-m.echCommands:
			trackECHARecord(command)
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := m.applyECHCommand(syncCtx, command)
			cancel()
			if err != nil {
				pendingECH[command.hostname] = command
				log.Warn().Err(err).Str("hostname", command.hostname).Msg("apply ECH dns command")
			} else {
				delete(pendingECH, command.hostname)
			}
		case command := <-m.ensCommands:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := m.applyENSCommand(syncCtx, command)
			cancel()
			if err != nil {
				pendingENS[command.hostname] = command
				log.Warn().Err(err).Str("hostname", command.hostname).Msg("apply ENS dns command")
			} else {
				delete(pendingENS, command.hostname)
			}
		case <-dnsTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := m.syncDNS(syncCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync managed dns records")
			}
		case <-retryTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := syncChangedARecords(syncCtx)
			m.commandMu.RLock()
			pendingDNSAddress := m.pendingDNSAddress
			m.commandMu.RUnlock()
			if pendingDNSAddress {
				err = errors.Join(err, m.syncDNS(syncCtx))
			}
			// Embedded signing remains pending: it does not authenticate the
			// parent chain and must not suppress DNSSEC synchronization.
			if m.cfg.ENSGaslessEnabled && !m.ENSStatus().Verified {
				err = errors.Join(err, m.syncENSDNSSEC(syncCtx))
			}
			err = errors.Join(err, flushCommands(syncCtx))
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync dns records")
			}
		case <-renewTicker.C:
			_, _, manual, err := m.manualCertificateOverride()
			if err != nil || manual || !m.shouldRenew() {
				continue
			}
			renewCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err = m.provision(renewCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("renew acme certificate")
			}
		}
	}
}
