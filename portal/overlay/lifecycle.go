package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/rs/zerolog/log"
	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func (r *Runtime) Start(ctx context.Context) error {
	if r == nil {
		return errOverlayRuntimeIsUnavailable
	}
	file, err := os.Open(r.config.ConfigPath)
	if err != nil {
		return err
	}
	defer file.Close()
	defaults := ivnp.DefaultRouterConfig()
	cfg := &defaults
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("decode IVNP RouterConfig JSON: %w", err)
	}
	if cfg == nil || cfg.Logger != nil || cfg.Resolver != nil {
		return errIvnpConfigurationMustJSONObjectWithout
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errIvnpConfigurationMustContainExactlyOne
	}
	router, err := ivnp.NewRouter(ctx, *cfg)
	if err != nil {
		return err
	}
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.router = router
	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil || r.router == nil {
		return errOverlayRuntimeIsNotStarted
	}
	stop := context.AfterFunc(ctx, r.Close)
	defer stop()
	defer r.Close()
	listener, destination, err := r.establishRunListener()
	if err != nil {
		return err
	}
	if listener == nil {
		return nil
	}
	defer r.ready.Store(false)
	log.Info().Str("destination", destination).Msg("relay overlay ready")
	return r.serveRunInbound(listener)
}

func (r *Runtime) establishRunListener() (net.Listener, string, error) {
	endpoint, err := r.router.NewDestination(r.ctx, ivnp.DefaultDestinationConfig())
	if r.stoppedBy(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	listener, err := endpoint.ListenContext(r.ctx, "i2p", ":"+types.OverlayStreamPort)
	if r.stoppedBy(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	destination, ok := r.publishRunEndpoint(endpoint)
	if !ok {
		return nil, "", nil
	}
	return listener, destination, nil
}

func (r *Runtime) stoppedBy(err error) bool {
	return err != nil && r.ctx.Err() != nil
}

func (r *Runtime) publishRunEndpoint(endpoint interface {
	B32() string
	DialContext(context.Context, string, string) (net.Conn, error)
}) (string, bool) {
	r.lifecycleMu.Lock()
	if r.ctx.Err() != nil {
		r.lifecycleMu.Unlock()
		return "", false
	}
	r.endpoint = endpoint
	r.ready.Store(true)
	r.lifecycleMu.Unlock()
	return endpoint.B32(), true
}

func (r *Runtime) serveRunInbound(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if r.stoppedBy(err) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, perr := peerDestination(conn); perr != nil {
			closeNow(conn)
			continue
		}
		select {
		case r.inbound <- struct{}{}:
			go func() {
				defer func() { <-r.inbound }()
				r.acceptReverse(conn)
			}()
		default:
			closeNow(conn)
		}
	}
}
