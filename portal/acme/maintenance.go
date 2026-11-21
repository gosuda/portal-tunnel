package acme

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"time"

	"github.com/rs/zerolog/log"
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

type maintenanceLoopState struct {
	lastPublicIPs          map[bool]string
	consecutiveDNSFailures int
	renewTimer             *time.Timer
	dnsTicker              *time.Ticker
	retryTimer             *time.Timer
}

func (m *Manager) maintenanceLoop(ctx context.Context) {
	defer m.wg.Done()
	state := m.maintenanceLoopNewState()
	defer state.renewTimer.Stop()
	defer state.dnsTicker.Stop()
	defer state.retryTimer.Stop()
	for {
		select {
		case <-m.stopCh:
			syncCtx, cancel := context.WithTimeout(m.stopCtx, defaultSyncTimeout)
			m.stopErr = m.maintenanceLoopApplyPendingENS(syncCtx, state)
			cancel()
			if m.stopErr != nil {
				log.Warn().Err(m.stopErr).Str("base_domain", m.cfg.BaseDomain).Msg("flush dns records")
			}
			return
		case command := <-m.ensCommands:
			m.maintenanceLoopHandleENSCommand(ctx, state, command)
		case <-state.dnsTicker.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			publicIPs, err := m.maintenanceLoopSyncDNSAttempt(syncCtx, state)
			err = errors.Join(err, m.syncChangedAddressRecords(syncCtx, state, publicIPs))
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync managed dns records")
			}
		case <-state.retryTimer.C:
			syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
			err := m.maintenanceLoopSyncRetryTick(syncCtx, state)
			cancel()
			if err != nil {
				log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("sync dns records")
			}
		case <-state.renewTimer.C:
			state.renewTimer.Reset(m.maintenanceLoopRenewTick(ctx))
		}
	}
}

func (m *Manager) maintenanceLoopNewState() *maintenanceLoopState {
	state := &maintenanceLoopState{
		lastPublicIPs: make(map[bool]string),
	}
	m.commandMu.RLock()
	state.consecutiveDNSFailures = 0
	if m.pendingDNSAddress {
		state.consecutiveDNSFailures = 1
		log.Info().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address pending: refusing queries until the public ip syncs")
	}
	m.commandMu.RUnlock()
	state.renewTimer = time.NewTimer(defaultRenewInterval)
	state.dnsTicker = time.NewTicker(defaultManagedDNSSyncInterval)
	state.retryTimer = time.NewTimer(nextSyncDelay(state.consecutiveDNSFailures))
	return state
}

func (m *Manager) syncChangedAddressRecords(ctx context.Context, state *maintenanceLoopState, publicIPs []string) error {
	var syncErr error
	for _, publicIP := range publicIPs {
		ipv4 := net.ParseIP(publicIP).To4() != nil
		if publicIP == state.lastPublicIPs[ipv4] {
			continue
		}
		if err := m.syncTrackedENSGaslessHostAddressRecords(ctx, publicIP); err != nil {
			syncErr = errors.Join(syncErr, err)
			continue
		}
		state.lastPublicIPs[ipv4] = publicIP
	}
	return syncErr
}

func (m *Manager) maintenanceLoopApplyPendingENS(ctx context.Context, state *maintenanceLoopState) error {
	m.commandMu.RLock()
	pending := maps.Clone(m.pendingENS)
	m.commandMu.RUnlock()
	var err error
	for _, command := range pending {
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		syncCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
		commandErr := m.applyENSCommand(syncCtx, command)
		cancel()
		if commandErr != nil {
			err = errors.Join(err, commandErr)
		} else {
			m.finishENSCommand(state, command)
		}
	}
	return err
}

func (m *Manager) maintenanceLoopRearmRetryTimer(state *maintenanceLoopState) {
	if !state.retryTimer.Stop() {
		select {
		case <-state.retryTimer.C:
		default:
		}
	}
	state.retryTimer.Reset(nextSyncDelay(state.consecutiveDNSFailures))
}

func (m *Manager) maintenanceLoopSyncDNSAttempt(ctx context.Context, state *maintenanceLoopState) ([]string, error) {
	publicIPs, err := m.syncDNS(ctx)
	m.commandMu.RLock()
	pendingDNSAddress := m.pendingDNSAddress
	m.commandMu.RUnlock()
	if pendingDNSAddress {
		if state.consecutiveDNSFailures == 0 {
			log.Info().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address pending: refusing queries until the public ip syncs")
		}
		state.consecutiveDNSFailures++
	} else {
		if state.consecutiveDNSFailures > 0 {
			log.Debug().Str("base_domain", m.cfg.BaseDomain).Msg("embedded dns address synced")
		}
		state.consecutiveDNSFailures = 0
	}
	m.maintenanceLoopRearmRetryTimer(state)
	return publicIPs, err
}

func (m *Manager) syncRetryTickAttempt(ctx context.Context, state *maintenanceLoopState) ([]string, bool, error) {
	m.commandMu.RLock()
	pendingDNSAddress := m.pendingDNSAddress
	m.commandMu.RUnlock()
	if pendingDNSAddress {
		publicIPs, err := m.maintenanceLoopSyncDNSAttempt(ctx, state)
		m.commandMu.RLock()
		pendingDNSAddress = m.pendingDNSAddress
		m.commandMu.RUnlock()
		return publicIPs, pendingDNSAddress, err
	}
	state.consecutiveDNSFailures = 0
	m.maintenanceLoopRearmRetryTimer(state)
	if m.cfg.ENSGaslessEnabled {
		publicIPs, err := m.publicIPs(ctx)
		return publicIPs, pendingDNSAddress, err
	}
	return nil, pendingDNSAddress, nil
}

func (m *Manager) maintenanceLoopSyncRetryTick(ctx context.Context, state *maintenanceLoopState) error {
	publicIPs, pendingDNSAddress, err := m.syncRetryTickAttempt(ctx, state)
	if !pendingDNSAddress && err != nil {
		err = fmt.Errorf("detect public ip: %w", err)
	}
	err = errors.Join(err, m.syncChangedAddressRecords(ctx, state, publicIPs))
	if m.cfg.ENSGaslessEnabled && !m.ENSStatus().Verified {
		err = errors.Join(err, m.syncENSDNSSEC(ctx))
	}
	return errors.Join(err, m.maintenanceLoopApplyPendingENS(ctx, state))
}

func (m *Manager) maintenanceLoopRenewTick(ctx context.Context) time.Duration {
	if _, _, manual, err := m.manualCertificateOverride(); err != nil || manual {
		return defaultRenewInterval
	}
	checkCtx, cancel := context.WithTimeout(ctx, defaultSyncTimeout)
	needsRenewal, replacesCertID, recheck := m.shouldRenew(checkCtx)
	cancel()
	if !needsRenewal {
		return recheck
	}
	// DNS propagation uses the provider's configured budget, which can exceed
	// the short DNS-sync/ARI timeout. Shutdown still cancels the whole order.
	if err := m.provision(ctx, replacesCertID); err != nil {
		log.Warn().Err(err).Str("base_domain", m.cfg.BaseDomain).Msg("renew acme certificate")
	}
	return defaultRenewInterval
}

func (m *Manager) maintenanceLoopHandleENSCommand(ctx context.Context, state *maintenanceLoopState, command ensDNSCommand) {
	err := m.maintenanceLoopApplyPendingENS(ctx, state)
	if err != nil {
		log.Warn().Err(err).Msg("apply lease dns commands")
	}
	if command.ready != nil {
		command.ready <- m.checkLeaseDNS(command.hostname)
	}
}

func (m *Manager) finishENSCommand(state *maintenanceLoopState, command ensDNSCommand) {
	m.commandMu.Lock()
	// A policy change or registration may have replaced the intent while DNS
	// I/O was running. Completing old work must not discard that newer work.
	if current, exists := m.pendingENS[command.hostname]; exists && current == command {
		delete(m.pendingENS, command.hostname)
	}
	m.commandMu.Unlock()
	if command.remove {
		return
	}
	clear(state.lastPublicIPs)
}
