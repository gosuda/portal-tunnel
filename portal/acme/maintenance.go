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

// dnsRetryBackoffs schedules the early retries while the embedded zone is
// still waiting for its public address. Once the table is exhausted the
// regular interval applies again.
var dnsRetryBackoffs = [...]time.Duration{
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

// nextSyncDelay returns the wait before the next DNS sync attempt.
// consecutiveFailures counts attempts that left the embedded DNS address
// still pending; zero means synced, so the regular cadence applies.
func nextSyncDelay(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 || consecutiveFailures > len(dnsRetryBackoffs) {
		return defaultDNSRetryInterval
	}
	return dnsRetryBackoffs[consecutiveFailures-1]
}

func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()
	pendingENS := make(map[string]ensDNSCommand)
	lastPublicIP := ""
	syncChangedARecords := func(ctx context.Context, publicIP string) error {
		if publicIP == "" || publicIP == lastPublicIP {
			return nil
		}

		var syncErr error
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
			}
		}
		return err
	}

	renewTicker := time.NewTicker(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultManagedDNSSyncInterval)
	// A timer instead of a ticker lets the pending embedded DNS address follow
	// the fast early retry schedule instead of waiting out the full interval.
	// EnsureCertificate has usually run before Start, so the zone can already
	// be pending on its address right after a relay restart.
	m.commandMu.RLock()
	consecutiveDNSFailures := 0
	if m.pendingDNSAddress {
		consecutiveDNSFailures = 1
	}
	m.commandMu.RUnlock()
	retryTimer := time.NewTimer(nextSyncDelay(consecutiveDNSFailures))
	defer renewTicker.Stop()
	defer dnsTicker.Stop()
	defer retryTimer.Stop()

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
			}
		case <-dnsTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			_, err := m.syncDNS(syncCtx)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync managed dns records")
			}
		case <-retryTimer.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			m.commandMu.RLock()
			pendingDNSAddress := m.pendingDNSAddress
			m.commandMu.RUnlock()
			var publicIP string
			var err error
			if pendingDNSAddress {
				publicIP, err = m.syncDNS(syncCtx)
				m.commandMu.RLock()
				pendingDNSAddress = m.pendingDNSAddress
				m.commandMu.RUnlock()
				if pendingDNSAddress {
					consecutiveDNSFailures++
				} else {
					consecutiveDNSFailures = 0
				}
			} else {
				consecutiveDNSFailures = 0
				if m.cfg.ENSGaslessEnabled {
					publicIP, err = utils.ResolvePublicIPv4(syncCtx)
				}
			}
			if !pendingDNSAddress && err != nil {
				err = fmt.Errorf("detect public ip: %w", err)
			}
			err = errors.Join(err, syncChangedARecords(syncCtx, publicIP))
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
			retryTimer.Reset(nextSyncDelay(consecutiveDNSFailures))
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
