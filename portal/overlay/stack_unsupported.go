//go:build !linux && !darwin && !windows && !freebsd && !openbsd

package overlay

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"github.com/gosuda/portal-tunnel/v2/types"
)

var errUnsupportedOverlay = fmt.Errorf("wireguard overlay is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)

type stack struct{}

func newStack(Config) (*stack, error) {
	return nil, errUnsupportedOverlay
}

func (*stack) ListenTCP(int) (net.Listener, error) {
	return nil, errUnsupportedOverlay
}

func (*stack) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errUnsupportedOverlay
}

func (*stack) ApplyPeers([]types.RelayDescriptor) error {
	return errUnsupportedOverlay
}

func (*stack) Close() error {
	return nil
}
