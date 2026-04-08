package discovery

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type RelayLocalState struct {
	Banned              bool
	Advertised          bool
	Expired             bool
	ConsecutiveFailures int
}

const discoveryRecoveryFailures = 3

// RelaySet owns the current discovery state:
// explicit bootstrap relay URLs, the latest descriptor seen for each relay,
// and the minimal local state required to ban or expire a relay.
type RelaySet struct {
	mu                 sync.RWMutex
	bootstrapRelayURLs []string
	relayKeysByURL     map[string]string
	relays             map[string]types.RelayDescriptor
	localByURL         map[string]*RelayLocalState
	activeRelayURLs    []string
	activeRelays       []types.RelayDescriptor
	selfRelayKey       string
	selfRelayURL       string
}

func NewRelaySet() *RelaySet {
	return &RelaySet{
		relayKeysByURL: make(map[string]string),
		relays:         make(map[string]types.RelayDescriptor),
		localByURL:     make(map[string]*RelayLocalState),
	}
}

func (s *RelaySet) getOrCreateLocalState(relayURL string) *RelayLocalState {
	state := s.localByURL[relayURL]
	if state == nil {
		state = &RelayLocalState{}
		s.localByURL[relayURL] = state
	}
	return state
}

func relayExpiredAt(desc types.RelayDescriptor, state *RelayLocalState, now time.Time) bool {
	if state.Expired {
		return true
	}
	if desc.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !desc.ExpiresAt.After(now)
}

func (s *RelaySet) bootstrapRelayURLSetLocked() map[string]struct{} {
	if len(s.bootstrapRelayURLs) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(s.bootstrapRelayURLs))
	for _, relayURL := range s.bootstrapRelayURLs {
		out[relayURL] = struct{}{}
	}
	return out
}

func (s *RelaySet) descriptorByURLLocked(relayURL string) (types.RelayDescriptor, bool) {
	relayKey, ok := s.relayKeysByURL[relayURL]
	if !ok {
		return types.RelayDescriptor{}, false
	}
	desc, ok := s.relays[relayKey]
	return desc, ok
}

func (s *RelaySet) isSelfRelayURLLocked(relayURL string) bool {
	if s == nil {
		return false
	}
	relayURL = strings.TrimSpace(relayURL)
	return relayURL != "" && s.selfRelayURL != "" && relayURL == s.selfRelayURL
}

func (s *RelaySet) isSelfRelayDescriptorLocked(desc types.RelayDescriptor) bool {
	if s == nil {
		return false
	}
	if s.selfRelayKey != "" {
		if relayKey := desc.Key(); relayKey != "" && relayKey == s.selfRelayKey {
			return true
		}
	}
	return s.isSelfRelayURLLocked(desc.APIHTTPSAddr)
}

func (s *RelaySet) removeSelfRelayLocked() {
	if s == nil {
		return
	}
	if s.selfRelayURL != "" {
		filtered := s.bootstrapRelayURLs[:0]
		for _, relayURL := range s.bootstrapRelayURLs {
			if s.isSelfRelayURLLocked(relayURL) {
				continue
			}
			filtered = append(filtered, relayURL)
		}
		s.bootstrapRelayURLs = filtered

		delete(s.localByURL, s.selfRelayURL)
		delete(s.relayKeysByURL, s.selfRelayURL)
	}
	if s.selfRelayKey != "" {
		if desc, ok := s.relays[s.selfRelayKey]; ok {
			delete(s.localByURL, desc.APIHTTPSAddr)
			delete(s.relayKeysByURL, desc.APIHTTPSAddr)
		}
		delete(s.relays, s.selfRelayKey)
	}
}

func (s *RelaySet) SetSelfRelay(identity types.Identity, relayURL string) error {
	if s == nil {
		return nil
	}
	relayURL = strings.TrimSpace(relayURL)
	if relayURL != "" {
		normalized, err := utils.NormalizeRelayURL(relayURL)
		if err != nil {
			return err
		}
		relayURL = normalized
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfRelayKey = identity.Key()
	s.selfRelayURL = relayURL
	s.removeSelfRelayLocked()
	s.syncActiveLocked(time.Now().UTC())
	return nil
}

func (s *RelaySet) syncActiveLocked(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	activeRelayURLs := make([]string, 0, len(s.bootstrapRelayURLs)+len(s.relays))
	activeRelays := make([]types.RelayDescriptor, 0, len(s.relays))
	seen := make(map[string]struct{}, len(s.bootstrapRelayURLs)+len(s.relays))
	for _, relayURL := range s.bootstrapRelayURLs {
		if s.isSelfRelayURLLocked(relayURL) {
			continue
		}
		state := s.getOrCreateLocalState(relayURL)
		if state.Banned {
			continue
		}
		seen[relayURL] = struct{}{}
		activeRelayURLs = append(activeRelayURLs, relayURL)
		desc, ok := s.descriptorByURLLocked(relayURL)
		if !ok || desc.APIHTTPSAddr == "" || !state.Advertised || relayExpiredAt(desc, state, now) {
			continue
		}
		activeRelays = append(activeRelays, desc)
	}

	discovered := make([]types.RelayDescriptor, 0, len(s.relays))
	for _, desc := range s.relays {
		if s.isSelfRelayDescriptorLocked(desc) {
			continue
		}
		relayURL := strings.TrimSpace(desc.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}
		state := s.getOrCreateLocalState(relayURL)
		if state.Banned || !state.Advertised || relayExpiredAt(desc, state, now) {
			continue
		}
		seen[relayURL] = struct{}{}
		discovered = append(discovered, desc)
	}
	sort.Slice(discovered, func(i, j int) bool {
		return discovered[i].APIHTTPSAddr < discovered[j].APIHTTPSAddr
	})
	for _, desc := range discovered {
		activeRelayURLs = append(activeRelayURLs, desc.APIHTTPSAddr)
		activeRelays = append(activeRelays, desc)
	}

	s.activeRelayURLs = activeRelayURLs
	s.activeRelays = activeRelays
}

func (s *RelaySet) ActiveRelayURLs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.activeRelayURLs) == 0 {
		return nil
	}
	return append([]string(nil), s.activeRelayURLs...)
}

func (s *RelaySet) bootstrapDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.bootstrapRelayURLs) == 0 {
		return nil
	}

	out := make([]types.RelayDescriptor, 0, len(s.bootstrapRelayURLs))
	for _, relayURL := range s.bootstrapRelayURLs {
		if s.isSelfRelayURLLocked(relayURL) {
			continue
		}
		if s.getOrCreateLocalState(relayURL).Banned {
			continue
		}
		if desc, ok := s.descriptorByURLLocked(relayURL); ok && desc.APIHTTPSAddr != "" {
			out = append(out, desc)
			continue
		}
		out = append(out, types.RelayDescriptor{
			Identity: types.Identity{
				Name: utils.PortalRootHost(relayURL),
			},
			APIHTTPSAddr: relayURL,
			RelayID:      relayURL,
			Version:      1,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *RelaySet) BootstrapDescriptors() []types.RelayDescriptor {
	descs := s.bootstrapDescriptors()
	if len(descs) == 0 {
		return nil
	}
	return append([]types.RelayDescriptor(nil), descs...)
}

func (s *RelaySet) ActiveRelayDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.activeRelays) == 0 {
		return nil
	}
	return append([]types.RelayDescriptor(nil), s.activeRelays...)
}

func (s *RelaySet) Snapshot() map[string]types.RelayState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.relays) == 0 {
		return nil
	}

	now := time.Now().UTC()
	snapshot := make(map[string]types.RelayState, len(s.relays))
	for identityKey, desc := range s.relays {
		state := s.localByURL[desc.APIHTTPSAddr]
		local := state
		if local == nil {
			local = &RelayLocalState{}
		}
		snapshot[identityKey] = types.RelayState{
			Descriptor:          desc,
			Advertised:          local.Advertised,
			Expired:             relayExpiredAt(desc, local, now),
			Banned:              local.Banned,
			ConsecutiveFailures: local.ConsecutiveFailures,
		}
	}
	return snapshot
}

func (s *RelaySet) confirmableDescriptors() []types.RelayDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.relays) == 0 {
		return nil
	}

	now := time.Now().UTC()
	bootstrapRelayURLs := s.bootstrapRelayURLSetLocked()
	out := make([]types.RelayDescriptor, 0, len(s.relays))
	for _, desc := range s.relays {
		if s.isSelfRelayDescriptorLocked(desc) {
			continue
		}
		relayURL := strings.TrimSpace(desc.APIHTTPSAddr)
		if relayURL == "" {
			continue
		}
		if _, ok := bootstrapRelayURLs[relayURL]; ok {
			continue
		}
		state := s.getOrCreateLocalState(relayURL)
		if state.Banned || relayExpiredAt(desc, state, now) {
			continue
		}
		out = append(out, desc)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].APIHTTPSAddr < out[j].APIHTTPSAddr
	})
	return out
}

func (s *RelaySet) BanRelayURL(relayURL string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return
	}
	state := s.getOrCreateLocalState(relayURL)
	if state.Banned {
		return
	}
	state.Banned = true
	s.syncActiveLocked(time.Now().UTC())
}

func (s *RelaySet) SetBootstrapRelayURLs(relayURLs []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := make([]string, 0, len(relayURLs))
	seen := make(map[string]struct{}, len(relayURLs))
	for _, relayURL := range relayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}
		if s.isSelfRelayURLLocked(relayURL) {
			continue
		}
		if _, ok := seen[relayURL]; ok {
			continue
		}
		seen[relayURL] = struct{}{}
		filtered = append(filtered, relayURL)
		s.getOrCreateLocalState(relayURL)
	}

	for _, relayURL := range s.bootstrapRelayURLs {
		if _, ok := seen[relayURL]; ok {
			continue
		}
		if _, ok := s.relayKeysByURL[relayURL]; ok {
			continue
		}
		delete(s.localByURL, relayURL)
	}
	s.bootstrapRelayURLs = filtered
	s.syncActiveLocked(time.Now().UTC())
}

func (s *RelaySet) registerDescriptorLocked(desc types.RelayDescriptor) error {
	normalized, err := NormalizeDescriptor(desc)
	if err != nil {
		return err
	}
	relayKey := normalized.Key()
	if relayKey == "" {
		return errors.New("descriptor identity is required")
	}
	if knownRelayKey, ok := s.relayKeysByURL[normalized.APIHTTPSAddr]; ok && knownRelayKey != relayKey {
		return errors.New("descriptor identity does not match known relay url")
	}

	previous := s.relays[relayKey]
	previousURL := strings.TrimSpace(previous.APIHTTPSAddr)
	if previousURL != "" && previousURL != normalized.APIHTTPSAddr {
		delete(s.relayKeysByURL, previousURL)
		if _, ok := s.relayKeysByURL[previousURL]; !ok {
			keepBootstrapState := false
			for _, bootstrapURL := range s.bootstrapRelayURLs {
				if bootstrapURL == previousURL {
					keepBootstrapState = true
					break
				}
			}
			if !keepBootstrapState {
				delete(s.localByURL, previousURL)
			}
		}
	}

	s.relays[relayKey] = normalized
	s.relayKeysByURL[normalized.APIHTTPSAddr] = relayKey
	s.getOrCreateLocalState(normalized.APIHTTPSAddr)
	return nil
}

func (s *RelaySet) ApplyRelayDiscoveryResponse(targetIdentity types.Identity, targetURL string, resp types.DiscoveryResponse, now time.Time) error {
	if s == nil {
		return nil
	}
	if strings.TrimSpace(targetIdentity.Name) == "" && strings.TrimSpace(targetIdentity.Address) == "" {
		return errors.New("target relay identity is required")
	}

	selfDescriptor, relayDescriptors, err := ValidateRelayDiscoveryResponse(resp, now)
	if err != nil {
		return err
	}
	if err := ValidateDescriptorTarget(selfDescriptor, targetIdentity, targetURL); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.registerDescriptorLocked(selfDescriptor); err != nil {
		return err
	}
	selfState := s.getOrCreateLocalState(selfDescriptor.APIHTTPSAddr)
	selfState.Advertised = true
	selfState.Expired = false
	selfState.ConsecutiveFailures = 0

	for _, relayDescriptor := range relayDescriptors {
		if s.isSelfRelayDescriptorLocked(relayDescriptor) {
			continue
		}
		if err := s.registerDescriptorLocked(relayDescriptor); err != nil {
			log.Warn().
				Err(err).
				Str("relay", relayDescriptor.APIHTTPSAddr).
				Msg("skipping conflicting discovery relay hint")
			continue
		}
		state := s.getOrCreateLocalState(relayDescriptor.APIHTTPSAddr)
		switch {
		case state.Expired:
			// Fresh hint re-enables direct confirmation but must not restore
			// advertisement until the relay confirms itself again.
			state.Advertised = false
			state.Expired = false
			state.ConsecutiveFailures = 0
		case !state.Advertised:
			state.Expired = false
			state.ConsecutiveFailures = 0
		}
	}
	s.syncActiveLocked(now)
	return nil
}

func (s *RelaySet) RecordDiscoveryFailure(identity types.Identity, relayURL string, err error) (expired bool, expireReason string, consecutiveFailures int) {
	if s == nil {
		return false, "", 0
	}
	relayKey := identity.Key()
	if relayKey == "" {
		return false, "", 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	desc, ok := s.relays[relayKey]
	if !ok {
		return false, "", 0
	}
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" || s.relayKeysByURL[relayURL] != relayKey {
		relayURL = desc.APIHTTPSAddr
	}
	if relayURL == "" {
		return false, "", 0
	}

	state := s.getOrCreateLocalState(relayURL)
	state.ConsecutiveFailures++
	if !state.Expired && state.ConsecutiveFailures >= discoveryRecoveryFailures {
		state.Expired = true
		state.Advertised = false
		s.syncActiveLocked(time.Now().UTC())
		return true, "recovery", state.ConsecutiveFailures
	}

	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		state.Expired = true
		state.Advertised = false
		s.syncActiveLocked(time.Now().UTC())
		return true, "status", state.ConsecutiveFailures
	}
	return false, "", state.ConsecutiveFailures
}

func logBootstrapDiscoveryFailure(relayURL string, err error) {
	if statusCode, code, unavailable := DiscoveryUnavailableStatus(err); unavailable {
		event := log.Info().Str("relay", relayURL)
		if statusCode > 0 {
			event = event.Int("status_code", statusCode)
		}
		if code != "" {
			event = event.Str("code", code)
		}
		event.Msg("bootstrap relay discovery unavailable")
		return
	}

	log.Warn().
		Err(err).
		Str("relay", relayURL).
		Msg("bootstrap relay discovery failed")
}

func logDirectDiscoveryFailure(relayURL string, err error, expired bool, expireReason string, consecutiveFailures int) {
	event := log.Warn().
		Err(err).
		Str("relay", relayURL)
	if expired {
		event = event.
			Bool("expired", true).
			Str("reason", expireReason)
		if consecutiveFailures > 0 {
			event = event.Int("consecutive_failures", consecutiveFailures)
		}
	}
	event.Msg("direct relay discovery failed")
}

func (s *RelaySet) refresh(ctx context.Context, rootCAPEM []byte) {
	if s == nil {
		return
	}

	for _, bootstrap := range s.bootstrapDescriptors() {
		resp, err := DiscoverRelayDiscovery(ctx, bootstrap.APIHTTPSAddr, rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logBootstrapDiscoveryFailure(bootstrap.APIHTTPSAddr, err)
			continue
		}
		if err := s.ApplyRelayDiscoveryResponse(bootstrap.Identity, bootstrap.APIHTTPSAddr, resp, time.Now().UTC()); err != nil {
			log.Warn().
				Err(err).
				Str("relay", bootstrap.APIHTTPSAddr).
				Msg("bootstrap relay discovery failed")
		}
	}
	if ctx.Err() != nil {
		return
	}

	for _, relay := range s.confirmableDescriptors() {
		resp, err := DiscoverRelayDiscovery(ctx, relay.APIHTTPSAddr, rootCAPEM, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			expired, expireReason, consecutiveFailures := s.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, err)
			logDirectDiscoveryFailure(relay.APIHTTPSAddr, err, expired, expireReason, consecutiveFailures)
			continue
		}
		if err := s.ApplyRelayDiscoveryResponse(relay.Identity, relay.APIHTTPSAddr, resp, time.Now().UTC()); err != nil {
			expired, expireReason, consecutiveFailures := s.RecordDiscoveryFailure(relay.Identity, relay.APIHTTPSAddr, err)
			logDirectDiscoveryFailure(relay.APIHTTPSAddr, err, expired, expireReason, consecutiveFailures)
		}
	}
}

func (s *RelaySet) RunLoop(ctx context.Context, rootCAPEM []byte, syncRuntime func() error) error {
	if s == nil {
		return nil
	}

	ticker := time.NewTicker(types.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		s.refresh(ctx, rootCAPEM)
		if ctx.Err() != nil {
			return nil
		}
		if syncRuntime != nil {
			if err := syncRuntime(); err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
