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

	// A timer instead of a ticker lets the CA's ARI Retry-After and the expiry
	// floor set the next renewal check.
	renewTimer := time.NewTimer(defaultRenewInterval)
	dnsTicker := time.NewTicker(defaultManagedDNSSyncInterval)
	// A timer instead of a ticker lets the pending embedded DNS address follow
	// the fast early retry schedule instead of waiting out the full interval.
	// EnsureCertificate has usually run before Start, so the zone can already
	// be pending on its address right after a relay restart.
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

	// rearmRetryTimer stops, drains, and resets the retry timer. The drain is
	// required because resetting an already-fired timer would make it fire
	// immediately on every subsequent loop iteration.
	rearmRetryTimer := func() {
		if !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		retryTimer.Reset(nextSyncDelay(consecutiveDNSFailures))
	}
	// syncDNSAttempt centralizes the bookkeeping shared by the regular ticker
	// and the pending-address retry path: it tracks consecutive failures for
	// the early backoff and re-arms retryTimer on every attempt. This way a
	// pending episode discovered by the ticker engages the fast schedule
	// immediately instead of waiting out the currently armed interval, and the
	// operator sees one signal per pending transition rather than per query.
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

	// syncRetryTick runs one retry-cycle sync: it fast-retries a pending
	// embedded DNS address, refreshes public-ip address records, and keeps
	// ENS DNSSEC and queued commands moving.
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
		// Embedded signing remains pending: it does not authenticate the
		// parent chain and must not suppress DNSSEC synchronization.
		if m.cfg.ENSGaslessEnabled && !m.ENSStatus().Verified {
			err = errors.Join(err, m.syncENSDNSSEC(syncCtx))
		}
		return errors.Join(err, flushCommands(syncCtx))
	}
	// renewTick runs one certificate renewal check and returns the delay to
	// arm on renewTimer: the CA's ARI Retry-After or expiry floor when renewal
	// is deferred, and the regular interval otherwise.
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
