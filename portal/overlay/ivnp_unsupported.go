//go:build windows

package overlay

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	defaultIVNPDiscoveryPort = 7777
	defaultIVNPHopPort       = 7778
)

type IVNP struct{}

func NewIVNP(string, http.Handler, StreamHandler) (*IVNP, error) {
	return nil, errors.New("ivnp overlay is not supported on windows")
}

func (*IVNP) Destination() string { return "" }

func (*IVNP) Serve(context.Context) error {
	return errors.New("ivnp overlay is not supported on windows")
}

func (*IVNP) OpenHopStream(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("ivnp overlay is not supported on windows")
}

func (*IVNP) DiscoverRelay(context.Context, types.RelayDescriptor) (types.DiscoveryResponse, error) {
	return types.DiscoveryResponse{}, errors.New("ivnp overlay is not supported on windows")
}

func (*IVNP) Sync([]types.RelayDescriptor) error { return nil }

func (*IVNP) CanDiscover(types.RelayDescriptor) bool { return false }

func (*IVNP) DiscoveryInterval() time.Duration { return 2 * time.Minute }

func (*IVNP) MeasureDiscoveryRTT() bool { return false }

func (*IVNP) RecordDiscoveryFailures() bool { return false }

func (*IVNP) Shutdown(context.Context) error { return nil }
