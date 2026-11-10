package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
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

var dnsRetryBackoffs = [...]time.Duration{
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

func nextSyncDelay(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 || consecutiveFailures > len(dnsRetryBackoffs) {
		return defaultDNSRetryInterval
	}
	return dnsRetryBackoffs[consecutiveFailures-1]
}

func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()
	pendingENS := make(map[string]ensDNSCommand)
	lastPublicIPs := make(map[bool]string)
	syncChangedAddressRecords := func(ctx context.Context, publicIPs []string) error {
		var syncErr error
		for _, publicIP := range publicIPs {
			ipv4 := net.ParseIP(publicIP).To4() != nil
			if publicIP == lastPublicIPs[ipv4] {
				continue
			}
			if m.cfg.ENSGaslessEnabled {
				if err := m.syncTrackedENSGaslessHostAddressRecords(ctx, publicIP); err != nil {
					syncErr = errors.Join(syncErr, err)
					continue
				}
			}
			lastPublicIPs[ipv4] = publicIP
		}
		return syncErr
	}
	flushCommands := func(ctx context.Context) error {
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
		for hostname, command := range pendingENS {
			if commandErr := m.applyENSCommand(ctx, command); commandErr != nil {
				err = errors.Join(err, commandErr)
			} else {
				delete(pendingENS, hostname)
				if !command.remove {
					clear(lastPublicIPs)
				}
			}
		}
		return err
	}

	renewTimer := time.NewTimer(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultManagedDNSSyncInterval)
	m.commandMu.RLock()
	consecutiveDNSFailures := 0
	if m.pendingDNSAddress {
		consecutiveDNSFailures = 1
		log.Info().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address pending: refusing queries until the public ip syncs")
	}
	m.commandMu.RUnlock()
	retryTimer := time.NewTimer(nextSyncDelay(consecutiveDNSFailures))
	defer renewTimer.Stop()
	defer dnsTicker.Stop()
	defer retryTimer.Stop()

	rearmRetryTimer := func() {
		if !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		retryTimer.Reset(nextSyncDelay(consecutiveDNSFailures))
	}
	syncDNSAttempt := func(ctx context.Context) ([]string, error) {
		publicIPs, err := m.syncDNS(ctx)
		m.commandMu.RLock()
		pendingDNSAddress := m.pendingDNSAddress
		m.commandMu.RUnlock()
		if pendingDNSAddress {
			if consecutiveDNSFailures == 0 {
				log.Info().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address pending: refusing queries until the public ip syncs")
			}
			consecutiveDNSFailures++
		} else {
			if consecutiveDNSFailures > 0 {
				log.Debug().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address synced")
			}
			consecutiveDNSFailures = 0
		}
		rearmRetryTimer()
		return publicIPs, err
	}

	syncRetryTick := func(syncCtx context.Context) error {
		m.commandMu.RLock()
		pendingDNSAddress := m.pendingDNSAddress
		m.commandMu.RUnlock()
		var publicIPs []string
		var err error
		if pendingDNSAddress {
			publicIPs, err = syncDNSAttempt(syncCtx)
			m.commandMu.RLock()
			pendingDNSAddress = m.pendingDNSAddress
			m.commandMu.RUnlock()
		} else {
			consecutiveDNSFailures = 0
			rearmRetryTimer()
			if m.cfg.ENSGaslessEnabled {
				publicIPs, err = utils.ResolvePublicIPs(syncCtx)
			}
		}
		if !pendingDNSAddress && err != nil {
			err = fmt.Errorf("detect public ip: %w", err)
		}
		err = errors.Join(err, syncChangedAddressRecords(syncCtx, publicIPs))
		if m.cfg.ENSGaslessEnabled && !m.ENSStatus().Verified {
			err = errors.Join(err, m.syncENSDNSSEC(syncCtx))
		}
		return errors.Join(err, flushCommands(syncCtx))
	}
	renewTick := func(ctx context.Context) time.Duration {
		if _, _, manual, err := m.manualCertificateOverride(); err != nil || manual {
			return defaultRenewInterval
		}
		renewCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
		defer cancel()
		needsRenewal, replacesCertID, recheck := m.shouldRenew(renewCtx)
		if !needsRenewal {
			return recheck
		}
		if err := m.provision(renewCtx, replacesCertID); err != nil {
			log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("renew acme certificate")
		}
		return defaultRenewInterval
	}

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
		case command := <-m.ensCommands:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := m.applyENSCommand(syncCtx, command)
			cancel()
			if err != nil {
				pendingENS[command.hostname] = command
				log.Warn().Err(err).Str("hostname", command.hostname).Msg("apply ENS dns command")
			} else {
				delete(pendingENS, command.hostname)
				if !command.remove {
					clear(lastPublicIPs)
				}
			}
		case <-dnsTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			publicIPs, err := syncDNSAttempt(syncCtx)
			err = errors.Join(err, syncChangedAddressRecords(syncCtx, publicIPs))
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync managed dns records")
			}
		case <-retryTimer.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := syncRetryTick(syncCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync dns records")
			}
		case <-renewTimer.C:
			renewTimer.Reset(renewTick(ctx))
		}
	}
}
