package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRelayListenerOrLocalAddressRequired = errors.New("relay listener or local address is required")
	errLeastOneHTTPRouteRequired           = errors.New("at least one http route is required")
	errHTTPRoutePrefixIsRequired           = errors.New("http route prefix is required")
)

const (
	defaultHTTPReadHeaderTimeout = 30 * time.Second
	defaultHTTPShutdownTimeout   = 5 * time.Second
	defaultHTTPIdleTimeout       = 90 * time.Second
)

// RunHTTP serves handler on the relay listener and, when localAddr is set, on
// that local address too. Requests from the relay listener reach handler with
// X-Forwarded-Proto set to https. Do not use it on an exposure that enables
// WithTCP.
func RunHTTP(ctx context.Context, relayListener net.Listener, handler http.Handler, localAddr string) error {
	if relayListener == nil && localAddr == "" {
		return errRelayListenerOrLocalAddressRequired
	}
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	driver := newRunHTTPDriver(relayListener, handler, localAddr)
	driver.launchRunHTTPservers()
	return driver.waitRunHTTPResult(ctx)
}

type serveRunHTTPDriver struct {
	relayListener net.Listener
	relaySrv      *http.Server
	localSrv      *http.Server
	results       chan error
	shutdownOnce  sync.Once
	shutdownErr   error
}

func newRunHTTPDriver(relayListener net.Listener, handler http.Handler, localAddr string) *serveRunHTTPDriver {
	relaySrv := relayHTTPServer(relayListener, handler)
	localSrv := localHTTPServer(localAddr, handler)
	serverCount := 0
	if relaySrv != nil {
		serverCount++
	}
	if localSrv != nil {
		serverCount++
	}
	return &serveRunHTTPDriver{
		relayListener: relayListener,
		relaySrv:      relaySrv,
		localSrv:      localSrv,
		results:       make(chan error, serverCount),
	}
}

func (d *serveRunHTTPDriver) shutdownRunHTTP() error {
	d.shutdownOnce.Do(func() {
		d.shutdownErr = shutdownHTTPServers(d.localSrv, d.relaySrv)
	})
	return d.shutdownErr
}

func (d *serveRunHTTPDriver) launchRunHTTPservers() {
	if d.localSrv != nil {
		go func() {
			d.results <- normalizeHTTPServeError(d.localSrv.ListenAndServe(), "serve local http")
		}()
	}
	if d.relaySrv != nil {
		go func() {
			d.results <- normalizeHTTPServeError(d.relaySrv.Serve(d.relayListener), "serve relay http")
		}()
	}
}

func (d *serveRunHTTPDriver) waitRunHTTPResult(ctx context.Context) error {
	var serveErr error
	remaining := cap(d.results)
	ctxDone := ctx.Done()
	for remaining > 0 {
		select {
		case err := <-d.results:
			remaining--
			if err != nil {
				serveErr = errors.Join(serveErr, err)
				_ = d.shutdownRunHTTP()
			}
		case <-ctxDone:
			_ = d.shutdownRunHTTP()
			ctxDone = nil
		}
	}
	shutdownErr := d.shutdownErr
	if ctx.Err() != nil && shutdownErr != nil {
		log.Warn().Err(shutdownErr).Msg("http shutdown completed with cleanup errors")
		shutdownErr = nil
	}
	return errors.Join(serveErr, shutdownErr)
}

func relayHTTPServer(relayListener net.Listener, handler http.Handler) *http.Server {
	if relayListener == nil {
		return nil
	}
	return &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			utils.DelHeaderSpellings(r.Header, "X-Forwarded-Proto")
			r.Header.Set("X-Forwarded-Proto", "https")
			utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
		IdleTimeout:       defaultHTTPIdleTimeout,
	}
}

func localHTTPServer(localAddr string, handler http.Handler) *http.Server {
	if localAddr == "" {
		return nil
	}
	return &http.Server{
		Addr:              localAddr,
		Handler:           handler,
		ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
		IdleTimeout:       defaultHTTPIdleTimeout,
	}
}

func normalizeHTTPServeError(err error, prefix string) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("serve http %s: %w", prefix, err)
}

func shutdownHTTPServers(localSrv, relaySrv *http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultHTTPShutdownTimeout)
	defer cancel()

	var localErr error
	if localSrv != nil {
		localErr = localSrv.Shutdown(shutdownCtx)
		if errors.Is(localErr, http.ErrServerClosed) {
			localErr = nil
		}
	}

	var relayErr error
	if relaySrv != nil {
		relayErr = relaySrv.Shutdown(shutdownCtx)
		if errors.Is(relayErr, http.ErrServerClosed) {
			relayErr = nil
		}
	}

	return errors.Join(localErr, relayErr)
}
