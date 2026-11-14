package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

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
// WithTCP. For an Exposure, this enables HTTP/2 on its canonical Local TLS
// endpoint. Raw Expose/Proxy users remain HTTP/1.1-only. The handler rejects
// HTTP authorities that differ from the TLS server name.
func RunHTTP(ctx context.Context, relayListener net.Listener, handler http.Handler, localAddr string) error {
	if relayListener == nil && localAddr == "" {
		return errRelayListenerOrLocalAddressRequired
	}
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	driver := newRunHTTPDriver(relayListener, handler, localAddr)
	if exposure, ok := relayListener.(*Exposure); ok {
		exposure.enableHTTP2()
	}
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
			d.results <- normalizeHTTPServeError(d.relaySrv.Serve(httpTLSListener{d.relayListener}), "serve relay http")
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
	return errors.Join(serveErr, d.shutdownErr)
}

func relayHTTPServer(relayListener net.Listener, handler http.Handler) *http.Server {
	if relayListener == nil {
		return nil
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			strictAuthority := r.TLS != nil
			if state, ok := r.Context().Value(httpTLSStateKey{}).(httpTLSState); ok {
				strictAuthority = state.local
				if r.TLS == nil && state.connection.HandshakeComplete {
					r.TLS = &state.connection
				}
			}
			if strictAuthority && r.TLS.ServerName != "" && utils.NormalizeHostWithoutPort(r.Host) != utils.NormalizeHostname(r.TLS.ServerName) {
				http.Error(w, "authority does not match TLS server name", http.StatusMisdirectedRequest)
				return
			}
			utils.DelHeaderSpellings(r.Header, "X-Forwarded-Proto")
			r.Header.Set("X-Forwarded-Proto", "https")
			utils.DelHeaderSpellings(r.Header, types.PortalIdentityHeaders...)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
		IdleTimeout:       defaultHTTPIdleTimeout,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			for {
				switch wrapped := conn.(type) {
				case *exposureConn:
					conn = wrapped.Conn
				case *bufferedConn:
					conn = wrapped.Conn
				default:
					if stateful, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
						_, local := conn.(*tls.Conn)
						return context.WithValue(ctx, httpTLSStateKey{}, httpTLSState{connection: stateful.ConnectionState(), local: local})
					}
					return ctx
				}
			}
		},
	}
	// Configure the actual HTTP/2 server, not just ALPN. Native TLS connections
	// are returned directly by httpTLSListener for net/http's protocol dispatch.
	_ = http2.ConfigureServer(server, &http2.Server{})
	return server
}

type httpTLSStateKey struct{}

// Local TLS uses native crypto/tls connections. Keyless connections retain the
// legacy authority policy: a canonical SNI may carry its friendly alias Host,
// with application handlers still responsible for their allowed-host checks.
type httpTLSState struct {
	connection tls.ConnectionState
	local      bool
}
type httpTLSListener struct{ net.Listener }

func (l httpTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tracked, ok := conn.(*exposureConn); ok {
		if native, ok := tracked.Conn.(*tls.Conn); ok {
			return native, nil
		}
	}
	return conn, nil
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
