package sdk

import (
	"context"
	"errors"
	mathrand "math/rand/v2"
	"net"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func (m *mitmManager) run(ctx context.Context, ready <-chan struct{}) {
	if m.listener.cache != nil || runtime.GOOS == "js" {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-ready:
	}
	budget := rate.NewLimiter(rate.Every(defaultMITMProbeInterval), mitmProbeBurst)
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		if m.listener.readySessions.Load() > 0 {
			var stop bool
			backoff, stop = m.probeCycle(ctx, budget, backoff)
			if stop {
				return
			}
		}

		delay := min(time.Duration(mathrand.ExpFloat64()*float64(defaultMITMProbeInterval)), defaultMITMProbeMaxDelay)
		delay = max(delay, backoff)
		if !utils.SleepOrDone(ctx, delay) {
			return
		}
	}
}

func (m *mitmManager) probeCycle(ctx context.Context, budget *rate.Limiter, backoff time.Duration) (time.Duration, bool) {
	if err := budget.Wait(ctx); err != nil {
		return backoff, true
	}
	report, err := m.probeTLSPassthrough(ctx)
	if ctx.Err() != nil {
		return backoff, true
	}
	m.logResult(report, err)
	if err != nil || report.Reason == types.MITMProbeReasonProbeTimeout {
		if backoff == 0 {
			backoff = defaultMITMProbeRetryDelay
		} else {
			backoff = min(2*backoff, defaultMITMProbeMaxDelay)
		}
	} else {
		backoff = 0
	}
	return backoff, false
}

func (m *mitmManager) logResult(report mitmProbeReport, err error) {
	l := m.listener
	if l == nil {
		return
	}
	closed := false
	select {
	case <-l.doneCh:
		closed = true
	default:
	}
	relayURL := ""
	if l.api != nil && l.api.relayURL != nil {
		relayURL = l.api.relayURL.String()
	}
	switch {
	case closed:
		return
	case err != nil:
		if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return
		}
		log.Warn().
			Err(err).
			Str("relay_url", relayURL).
			Str("address", l.identity.Address).
			Msg("tls passthrough self-probe failed")
	case report.Reason == types.MITMProbeReasonProbeTimeout:
		log.Warn().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls self-probe timed out before passthrough could be verified")
	case report.Detected:
		m.reportProbeDetection(l, report)
	default:
		log.Debug().
			Str("relay_url", report.RelayURL).
			Str("public_url", report.PublicURL).
			Str("address", report.Address).
			Msg("tls passthrough self-probe passed")
	}
}

func (m *mitmManager) reportProbeDetection(l *listener, report mitmProbeReport) {
	event := log.Warn().
		Bool("ban_mitm", m.ban).
		Str("reason", report.Reason).
		Str("relay_url", report.RelayURL).
		Str("public_url", report.PublicURL).
		Str("address", report.Address)
	if m.ban {
		event.Msg("tls termination suspected by self-probe; closing listener")
		l.report(listenerStatus{state: RelayFailed, failure: RelayFailureMITM, err: errMITMDetected})
		_ = l.Close()
		return
	}
	event.Msg("tls termination suspected by self-probe")
}
