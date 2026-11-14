package agent

import (
	"cmp"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const managedTunnelRetryInterval = 30 * time.Second

type managedTunnel struct {
	mu  sync.RWMutex
	cfg TunnelConfig

	cancel    context.CancelFunc
	done      chan struct{}
	runtime   *tunnel.Runtime
	lastError string
	address   string
}

func (t *managedTunnel) Start(parent context.Context) {
	t.mu.Lock()
	if t.done != nil {
		t.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	t.cancel = cancel
	t.done = make(chan struct{})
	done := t.done
	t.mu.Unlock()

	go func() {
		defer close(done)
		t.runLoop(ctx)
	}()
}

func (t *managedTunnel) Stop(ctx context.Context) error {
	t.mu.Lock()
	cancel := t.cancel
	done := t.done
	t.cancel = nil
	t.done = nil
	if cancel != nil {
		cancel()
	}
	t.mu.Unlock()

	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *managedTunnel) ConnectRelay(relayURL string) error {
	t.mu.RLock()
	runtime := t.runtime
	t.mu.RUnlock()
	if runtime == nil {
		return errTunnelIsNotRunning
	}
	return runtime.Exposure.AddRelay(relayURL)
}

func (t *managedTunnel) DisconnectRelay(relayURL string) error {
	t.mu.RLock()
	runtime := t.runtime
	t.mu.RUnlock()
	if runtime == nil {
		return errTunnelIsNotRunning
	}
	return runtime.Exposure.RemoveRelay(relayURL)
}

func (t *managedTunnel) updateSettings() error {
	t.mu.RLock()
	runtime := t.runtime
	cfg := t.cfg
	t.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	spec, err := cfg.Spec()
	if err != nil {
		return err
	}
	return errors.Join(
		runtime.Exposure.UpdateMetadata(spec.Metadata),
		runtime.Exposure.SetMaxActiveRelays(spec.Relays.MaxActive),
	)
}

func (t *managedTunnel) Snapshot() AgentTunnelStatus {
	t.mu.RLock()
	cfg := t.cfg
	lastError := t.lastError
	runtime := t.runtime
	done := t.done
	address := t.address
	t.mu.RUnlock()
	return cfg.renderTunnelStatus(runtime, done, address, lastError)
}

func (cfg TunnelConfig) renderTunnelStatus(runtime *tunnel.Runtime, done chan struct{}, address, lastError string) AgentTunnelStatus {
	running := false
	if done != nil {
		select {
		case <-done:
		default:
			running = true
		}
	}

	state := "stopped"
	switch {
	case lastError != "":
		state = "error"
	case runtime != nil:
		state = "running"
	case running:
		state = "starting"
	}

	spec, _ := cfg.Spec()
	auth := cfg.AuthConfig
	status := AgentTunnelStatus{
		Address:                 address,
		ID:                      cfg.ID,
		Name:                    cfg.Name,
		State:                   state,
		TargetAddr:              cfg.TargetAddr,
		LastError:               lastError,
		Serve:                   cfg.Serve,
		Discovery:               spec.Relays.Discovery,
		Overlay:                 cfg.Overlay,
		MaxActiveRelays:         spec.Relays.MaxActive,
		Metadata:                spec.Metadata,
		AuthConfig:              auth.Public(),
		AuthOIDCClientSecretSet: auth.OIDCClientSecret != "",
		AuthSMTPPasswordSet:     auth.SMTPPassword != "",
		X402Config:              cfg.X402Config,
	}
	status.Endpoints = slices.Clone(status.Endpoints)
	attachTunnelLiveStatus(&status, cfg.Provider, spec.HTTP, runtime)
	return status
}

func attachTunnelLiveStatus(status *AgentTunnelStatus, provider string, httpSpec *tunnel.HTTPConfig, runtime *tunnel.Runtime) {
	hasProviderCheck := provider == appauth.ProviderOIDC || provider == appauth.ProviderSAML || provider == appauth.ProviderEmail
	if runtime != nil && hasProviderCheck {
		checked, err := runtime.AuthProviderCheck()
		status.AuthProviderChecked = checked
		if err != nil {
			status.AuthProviderError = err.Error()
		}
	}
	if httpSpec != nil {
		status.HTTPRoutes = httpSpec.Routes
	}
	if runtime != nil {
		status.Relays = agentRelayStatuses(runtime.Exposure.Relays())
	}
}

func agentRelayStatuses(relays []sdk.RelayStatus) []AgentRelayStatus {
	statuses := make([]AgentRelayStatus, 0, len(relays))
	for _, relay := range relays {
		aliasURL := ""
		if relay.State == sdk.RelayReady && !relay.Deselected {
			aliasURL = relay.AliasURL
		}
		var certificateError string
		if relay.CertificateError != nil {
			certificateError = relay.CertificateError.Error()
		}
		statuses = append(statuses, AgentRelayStatus{
			CertificateError: certificateError,
			RelayURL:         relay.RelayURL,
			PublicURL:        relay.PublicURL,
			LegacyURL:        relay.LegacyURL,
			AliasURL:         aliasURL,
			TCPAddr:          relay.TCPAddr,
			Version:          relay.Version,
			State:            relay.State,
			Failure:          relay.Failure,
			Approval:         relay.Approval,
		})
	}
	return statuses
}

func (t *managedTunnel) runLoop(ctx context.Context) {
	for {
		err := t.runOnce(ctx)
		t.mu.Lock()
		t.runtime = nil
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || err == nil {
			t.lastError = ""
		} else {
			t.lastError = err.Error()
		}
		t.mu.Unlock()

		if ctx.Err() != nil || errors.Is(err, context.Canceled) || err == nil {
			return
		}
		log.Warn().Err(err).Msg("managed tunnel stopped with error; retrying")
		if !utils.SleepOrDone(ctx, managedTunnelRetryInterval) {
			return
		}
	}
}

func (t *managedTunnel) runOnce(ctx context.Context) error {
	t.mu.Lock()
	cfg := t.cfg
	t.lastError = ""
	t.mu.Unlock()

	cfg.FacilitatorToken = cmp.Or(strings.TrimSpace(cfg.FacilitatorToken), strings.TrimSpace(os.Getenv("CSPR_CLOUD_API_KEY")))
	spec, err := cfg.Spec()
	if err != nil {
		return err
	}
	runtime, err := tunnel.Start(ctx, spec)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.runtime = runtime
	t.address = runtime.Identity.Address
	t.lastError = ""
	t.mu.Unlock()

	defer runtime.Close()
	err = runtime.Run(ctx)
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return ctx.Err()
	}
	return err
}
