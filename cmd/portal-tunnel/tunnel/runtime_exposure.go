package tunnel

import (
	"cmp"
	"context"
	"fmt"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func exposeTunnelRuntime(ctx context.Context, spec Spec, listenerIdentity types.Identity, explicitRelayURLs []string) (*Runtime, error) {
	opts := buildExposureOptions(spec)
	exposure, err := sdk.Expose(ctx, listenerIdentity, explicitRelayURLs, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start relays: %w", err)
	}
	runtime := &Runtime{Identity: listenerIdentity, Exposure: exposure, target: spec.Transport.Target}
	if spec.Transport.UDP != nil {
		runtime.udpTarget = cmp.Or(spec.Transport.UDP.Target, spec.Transport.Target)
	}
	return runtime, nil
}
