package portal

import (
	"context"
	"errors"

	"github.com/gosuda/portal-tunnel/v2/sdk"
)

// ProxyConfig selects local TCP and UDP targets. At least one target is
// required.
type ProxyConfig struct {
	TCPTarget string
	UDPTarget string
}

// Proxy copies tenant streams to a local TCP target. It blocks until the
// exposure ends and closes the exposure afterwards.
func Proxy(ctx context.Context, exposure *Exposure, target string) error {
	return ProxyWithConfig(ctx, exposure, ProxyConfig{TCPTarget: target})
}

// ProxyUDP copies relayed datagrams to a local UDP target. It blocks until
// the exposure ends and closes the exposure afterwards.
func ProxyUDP(ctx context.Context, exposure *Exposure, target string) error {
	return ProxyWithConfig(ctx, exposure, ProxyConfig{UDPTarget: target})
}

// ProxyWithConfig runs the TCP and UDP proxy loops together and closes the
// exposure after cancellation or the first terminal proxy error.
func ProxyWithConfig(ctx context.Context, exposure *Exposure, config ProxyConfig) error {
	if exposure == nil || exposure.inner == nil {
		return errors.New("portal: exposure is nil")
	}
	if config.TCPTarget == "" && config.UDPTarget == "" {
		return errors.New("portal: at least one proxy target is required")
	}
	return sdk.ProxyWithTargets(ctx, exposure.inner, config.TCPTarget, config.UDPTarget)
}
