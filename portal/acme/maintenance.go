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
	lastPublicIP := ""

	renewTicker := time.NewTicker(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultManagedDNSSyncInterval)
	retryTicker := time.NewTicker(defaultDNSRetryInterval)
	defer renewTicker.Stop()
	defer dnsTicker.Stop()
	defer retryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case command := <-m.echCommands:
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
			var err error
			if m.cfg.ENSGaslessEnabled {
				publicIP, resolveErr := utils.ResolvePublicIPv4(syncCtx)
				if resolveErr != nil {
					err = fmt.Errorf("detect public ip: %w", resolveErr)
				} else if publicIP != lastPublicIP {
					ensErr := m.syncTrackedENSGaslessHostARecords(syncCtx, publicIP)
					err = errors.Join(err, ensErr)
					if ensErr == nil {
						lastPublicIP = publicIP
					}
				}
				if !m.ENSStatus().Verified {
					err = errors.Join(err, m.syncENSDNSSEC(syncCtx))
				}
			}
		drainECH:
			for {
				select {
				case command := <-m.echCommands:
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
			for hostname, command := range pendingECH {
				if commandErr := m.applyECHCommand(syncCtx, command); commandErr != nil {
					err = errors.Join(err, commandErr)
				} else {
					delete(pendingECH, hostname)
				}
			}
			for hostname, command := range pendingENS {
				if commandErr := m.applyENSCommand(syncCtx, command); commandErr != nil {
					err = errors.Join(err, commandErr)
				} else {
					delete(pendingENS, hostname)
				}
			}
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync dns records")
			}
		case <-renewTicker.C:
			_, _, manual, err := m.manualCertificateOverride()
			if err != nil || manual || m.dns == nil || !m.shouldRenew() {
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
