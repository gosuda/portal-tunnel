//go:build linux || darwin

package overlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func startIVNP(ctx context.Context, configPath string) (network, net.Listener, string, func() error, error) {
	cfg, err := ivnp.LoadOrCreateConfig(configPath)
	if err != nil {
		return nil, nil, "", nil, err
	}
	// Portal uses only the embedded destination, never external proxy services.
	cfg.SAM.Enabled = false
	cfg.HTTPProxy.Enabled = false
	cfg.SOCKS5.Enabled = false
	cfg.Control.Enabled = false
	node, err := ivnp.New(cfg, ivnp.Options{})
	if err != nil {
		return nil, nil, "", nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = node.Close()
		}
	}()
	path := configPath + ".destination"
	encoded, err := os.ReadFile(path)
	var local *ivnp.LocalDestination
	switch {
	case err == nil:
		local, err = ivnp.ImportLocalDestination(encoded)
		clear(encoded)
	case errors.Is(err, os.ErrNotExist):
		local, err = ivnp.GenerateLegacyLocalDestination()
		if err == nil {
			encoded = make([]byte, local.PrivateEncodedLen())
			n, marshalErr := local.MarshalPrivateTo(encoded)
			if marshalErr != nil {
				err = marshalErr
			} else {
				err = utils.WriteFileAtomic(path, encoded[:n], 0o600)
			}
			clear(encoded)
		}
	}
	if err != nil {
		if local != nil {
			local.ReleaseSensitive()
		}
		return nil, nil, "", nil, fmt.Errorf("load IVNP destination: %w", err)
	}
	defer local.ReleaseSensitive()
	if err := node.Start(ctx); err != nil {
		return nil, nil, "", nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	endpoint, err := node.DestinationController().CreateDestination(readyCtx, ivnp.DestinationSpec{Local: local})
	if err != nil {
		return nil, nil, "", nil, err
	}
	ready, ok := endpoint.(ivnp.ReadyDestinationEndpoint)
	if !ok {
		return nil, nil, "", nil, errors.New("IVNP endpoint does not expose readiness")
	}
	if err := ready.WaitReady(readyCtx); err != nil {
		return nil, nil, "", nil, fmt.Errorf("IVNP destination readiness: %w", err)
	}
	listener, err := endpoint.ListenI2P(ctx, ":"+types.RelayOverlayPort)
	if err != nil {
		return nil, nil, "", nil, err
	}
	success = true
	return endpoint, listener, endpoint.B32(), func() error { return errors.Join(node.Close(), node.Wait()) }, nil
}
