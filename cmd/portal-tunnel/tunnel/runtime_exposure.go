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
	var pgnsCtrl *pgnsController
	effectiveIdentity := listenerIdentity
	relayURLs := explicitRelayURLs
	if spec.PGNS != nil {
		var err error
		pgnsCtrl, effectiveIdentity, err = preparePGNSRuntime(ctx, spec, listenerIdentity, explicitRelayURLs)
		if err != nil {
			return nil, fmt.Errorf("prepare pgns runtime: %w", err)
		}
		relayURLs = pgnsCtrl.relayURLs()
		opts = append(opts,
			sdk.WithTLSCertificate(pgnsCtrl.certFile, pgnsCtrl.keyFile),
			sdk.WithPGNS(pgnsCtrl.fqdn, pgnsCtrl.proof),
		)
	}
	exposure, err := sdk.Expose(ctx, effectiveIdentity, relayURLs, opts...)
	if err != nil {
		_ = pgnsCtrl.close()
		return nil, fmt.Errorf("failed to start relays: %w", err)
	}
	runtime := &Runtime{Identity: effectiveIdentity, Exposure: exposure, target: spec.Transport.Target, pgns: pgnsCtrl}
	if spec.Transport.UDP != nil {
		runtime.udpTarget = cmp.Or(spec.Transport.UDP.Target, spec.Transport.Target)
	}
	if pgnsCtrl != nil {
		pgnsCtrl.start(ctx, exposure)
	}
	return runtime, nil
}
