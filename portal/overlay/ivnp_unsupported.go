//go:build !linux && !darwin

package overlay

import (
	"context"
	"errors"
	"net"
)

func startIVNP(context.Context, string) (network, net.Listener, string, func() error, error) {
	return nil, nil, "", nil, errors.New("IVNP relay overlay requires Linux or macOS")
}
