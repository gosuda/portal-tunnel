package discovery

import (
	"errors"
	"math/rand"
	"net/http"
	"slices"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

type RelayPolicy interface {
	SelectAggregate([]RelayState) []RelayState
	SelectConfirmed([]RelayState) []RelayState
	SelectPriority([]RelayState, ClientState) []string
	OnConfirmed(RelayState) RelayState
	OnUnconfirmed(RelayState) RelayState
	OnFailure(RelayState, error, int) (RelayState, bool, string)
	OnBanned(RelayState) RelayState
}

type DefaultRelayPolicy struct{}

const highDiscoveryRTTThreshold = 1 * time.Second

func (p DefaultRelayPolicy) SelectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, state := range states {
		if state.Banned {
			continue
		}
		if !state.Bootstrap && !state.hasObservedDescriptor() {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p DefaultRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	selected := p.SelectAggregate(states)
	out := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if !state.Confirmed {
			continue
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p DefaultRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []string {
	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	explicit := make([]string, 0, len(clientState.ExplicitRelayURLs))
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if clientState.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(clientState.ExplicitRelayURLs, relayURL) {
			explicit = append(explicit, relayURL)
			continue
		}
		autoPool = append(autoPool, state)
	}
	if len(explicit) == 0 && len(autoPool) == 0 {
		return nil
	}

	currentAuto := make([]string, 0, len(autoPool))
	confirmedAuto := make([]string, 0, len(autoPool))
	highRTTAuto := make([]string, 0, len(autoPool))
	remainingAuto := make([]string, 0, len(autoPool))
	for _, state := range autoPool {
		relayURL := state.Descriptor.APIHTTPSAddr
		switch {
		case slices.Contains(clientState.ActiveRelayURLs, relayURL):
			currentAuto = append(currentAuto, relayURL)
		case state.Confirmed && !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > highDiscoveryRTTThreshold:
			highRTTAuto = append(highRTTAuto, relayURL)
		case state.Confirmed:
			confirmedAuto = append(confirmedAuto, relayURL)
		default:
			remainingAuto = append(remainingAuto, relayURL)
		}
	}

	if len(confirmedAuto) > 1 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(confirmedAuto), func(i, j int) {
			confirmedAuto[i], confirmedAuto[j] = confirmedAuto[j], confirmedAuto[i]
		})
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	if len(remainingAuto) > 1 {
		rng.Shuffle(len(remainingAuto), func(i, j int) {
			remainingAuto[i], remainingAuto[j] = remainingAuto[j], remainingAuto[i]
		})
	}
	if len(highRTTAuto) > 1 {
		rng.Shuffle(len(highRTTAuto), func(i, j int) {
			highRTTAuto[i], highRTTAuto[j] = highRTTAuto[j], highRTTAuto[i]
		})
	}

	autoURLs := make([]string, 0, len(currentAuto)+len(confirmedAuto)+len(highRTTAuto)+len(remainingAuto))
	autoURLs = append(autoURLs, currentAuto...)
	autoURLs = append(autoURLs, confirmedAuto...)
	autoURLs = append(autoURLs, highRTTAuto...)
	autoURLs = append(autoURLs, remainingAuto...)
	if clientState.MaxActiveRelays > 0 && len(autoURLs) > clientState.MaxActiveRelays {
		autoURLs = autoURLs[:clientState.MaxActiveRelays]
	}

	out := make([]string, 0, len(explicit)+len(autoURLs))
	out = append(out, explicit...)
	out = append(out, autoURLs...)
	if len(out) == 0 {
		return nil
	}
	return out
}

func (DefaultRelayPolicy) OnConfirmed(state RelayState) RelayState {
	if state.Banned {
		return state
	}
	state.Confirmed = true
	return state
}

func (DefaultRelayPolicy) OnUnconfirmed(state RelayState) RelayState {
	state.Confirmed = false
	return state
}

func (DefaultRelayPolicy) OnFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	if state.Banned {
		return state, false, ""
	}
	state.consecutiveFailures++
	backOff := func(reason string) (RelayState, bool, string) {
		backoff := defaultDirectRecoveryBackoff
		for extra := state.consecutiveFailures - recoveryFailures; extra > 0; extra-- {
			if backoff >= maxDirectRecoveryBackoff/2 {
				backoff = maxDirectRecoveryBackoff
				break
			}
			backoff *= 2
		}
		state.nextDirectRefreshAt = time.Now().UTC().Add(backoff)
		return state, true, reason
	}
	var apiErr *types.APIRequestError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden ||
			apiErr.StatusCode == http.StatusNotFound ||
			apiErr.StatusCode == http.StatusGone) {
		return backOff("status")
	}
	if state.consecutiveFailures >= recoveryFailures {
		return backOff("recovery")
	}
	return state, false, ""
}

func (DefaultRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Banned = true
	state.Confirmed = false
	return state
}
