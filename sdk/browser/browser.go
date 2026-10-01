// Package browser is a portal connector for runtimes without sockets, such as a browser
// running WebAssembly. It registers a lease the way the SDK does, but reaches the relay
// over the multiplexed WebSocket reverse carrier, the one duplex channel such a runtime
// can open. It serves what a browser can: HTTPS through one relay, with tenant TLS
// terminated here.
//
// It is a separate connector rather than a build of the SDK, so the SDK and its native
// transport stay as they are.
package browser

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/sdk/internal/control"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	leaseTTL         = 2 * time.Minute
	renewBefore      = 30 * time.Second
	readyTarget      = 2
	retryWait        = 3 * time.Second
	handshakeTimeout = 30 * time.Second
	requestTimeout   = 30 * time.Second
)

// Listener holds a lease on one relay. Accept returns the visitor connections it
// receives, with tenant TLS already terminated.
type Listener struct {
	relayURL *url.URL
	identity types.Identity
	hostname string
	control  *control.Client
	chainPEM []byte
	stream   *transport.ClientStream
	accepted chan net.Conn

	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once

	mu    sync.Mutex
	lease lease
}

type lease struct {
	accessToken string
	reverse     types.ReverseEndpoint
	expiresAt   time.Time
	tenantTLS   *keyless.Client
}

// Listen registers id with the relay at relayURL and keeps the lease, registering again
// if it is lost, until ctx ends or the listener is closed. certificateChainPEM is the
// public signer chain supplied by the page hosting the socketless runtime.
func Listen(ctx context.Context, id types.Identity, relayURL string, certificateChainPEM []byte) (*Listener, error) {
	if len(certificateChainPEM) == 0 {
		return nil, errors.New("relay certificate chain is required")
	}
	normalized, err := utils.NormalizeRelayURL(relayURL)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}
	hostname, err := utils.LeaseHostname(id.Name, utils.PortalRootHost(normalized))
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: requestTimeout}
	l := &Listener{
		relayURL: parsed,
		identity: id.Copy(),
		hostname: hostname,
		control:  control.NewClient(parsed, httpClient),
		chainPEM: bytes.Clone(certificateChainPEM),
		stream:   transport.NewClientStream(handshakeTimeout),
		accepted: make(chan net.Conn),
		done:     make(chan struct{}),
	}
	if err := l.checkProtocol(ctx); err != nil {
		return nil, err
	}
	if err := l.register(ctx); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	go l.run(runCtx)
	return l, nil
}

// Accept waits for the next visitor connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close ends the lease and releases it on the relay.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		<-l.done

		l.mu.Lock()
		current := l.lease
		l.lease = lease{}
		l.mu.Unlock()
		if current.accessToken != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = l.control.Unregister(ctx, current.accessToken)
			cancel()
		}
		if current.tenantTLS != nil {
			err = errors.Join(err, current.tenantTLS.Close())
		}
	})
	return err
}

// Addr reports the lease hostname.
func (l *Listener) Addr() net.Addr {
	return leaseAddr(l.hostname)
}

// PublicURL is where visitors reach this listener.
func (l *Listener) PublicURL() string {
	host := l.hostname
	if port := l.relayURL.Port(); port != "" {
		host = net.JoinHostPort(l.hostname, port)
	}
	return (&url.URL{Scheme: l.relayURL.Scheme, Host: host}).String()
}

type leaseAddr string

func (a leaseAddr) Network() string { return "portal" }
func (a leaseAddr) String() string  { return string(a) }

func (l *Listener) run(ctx context.Context) {
	defer close(l.done)
	for {
		err := l.runLease(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Debug().Err(err).Str("relay_url", l.relayURL.String()).Msg("browser lease lost; registering again")
		for {
			if !utils.SleepOrDone(ctx, retryWait) {
				return
			}
			if err := l.register(ctx); err == nil {
				break
			}
		}
	}
}

// runLease serves one registration. The lease owns its carrier, so the WebSocket and
// every reverse connection on it end with the lease.
func (l *Listener) runLease(ctx context.Context) error {
	carrier := &reverseCarrier{listener: l}
	defer carrier.Close()

	group, leaseCtx := errgroup.WithContext(ctx)
	for range readyTarget {
		group.Go(func() error { return l.serveReverse(leaseCtx, carrier) })
	}
	group.Go(func() error { return l.renewLoop(leaseCtx) })
	return group.Wait()
}

func (l *Listener) serveReverse(ctx context.Context, carrier *reverseCarrier) error {
	for {
		conn, err := carrier.Open(ctx)
		if err == nil {
			conn, err = l.awaitVisitor(ctx, conn)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Debug().Err(err).Str("relay_url", l.relayURL.String()).Msg("browser reverse connection failed; retrying")
			if !utils.SleepOrDone(ctx, retryWait) {
				return ctx.Err()
			}
			continue
		}
		select {
		case l.accepted <- conn:
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		}
	}
}

// awaitVisitor parks conn in the relay's ready queue until a visitor claims it, then
// terminates tenant TLS on it.
func (l *Listener) awaitVisitor(ctx context.Context, conn net.Conn) (net.Conn, error) {
	session, err := l.stream.RunSession(ctx, conn)
	if err != nil {
		return nil, err
	}
	if len(session.Binding) == 0 {
		return session.Conn, nil
	}
	l.mu.Lock()
	tenantTLS := l.lease.tenantTLS
	l.mu.Unlock()
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	return tenantTLS.TerminateConn(handshakeCtx, session.Conn, session.Binding)
}

func (l *Listener) renewLoop(ctx context.Context) error {
	for {
		l.mu.Lock()
		expiresAt := l.lease.expiresAt
		l.mu.Unlock()
		if !utils.SleepOrDone(ctx, time.Until(expiresAt.Add(-renewBefore))) {
			return ctx.Err()
		}
		err := l.renew(ctx)
		if err == nil {
			continue
		}
		if staleLease(err) || !time.Now().Before(expiresAt) {
			return err
		}
		log.Debug().Err(err).Str("relay_url", l.relayURL.String()).Msg("browser lease renewal failed; retrying")
		if !utils.SleepOrDone(ctx, retryWait) {
			return ctx.Err()
		}
	}
}

func (l *Listener) checkProtocol(ctx context.Context) error {
	_, err := l.control.CheckProtocol(ctx)
	return err
}

func (l *Listener) register(ctx context.Context) error {
	resp, err := l.control.Register(ctx, types.RegisterChallengeRequest{
		Identity: l.identity,
		TTL:      int(leaseTTL / time.Second),
	}, "")
	if err != nil {
		return err
	}

	tenantTLS, err := keyless.NewClient(keyless.ClientConfig{
		RelayURL:            l.relayURL.String(),
		Hostname:            l.hostname,
		AccessToken:         resp.AccessToken,
		CertificateChainPEM: l.chainPEM,
	})
	if err != nil {
		_ = l.control.Unregister(context.Background(), resp.AccessToken)
		return err
	}

	l.mu.Lock()
	previous := l.lease
	l.lease = lease{accessToken: resp.AccessToken, reverse: resp.ReverseEndpoint, expiresAt: resp.ExpiresAt, tenantTLS: tenantTLS}
	l.mu.Unlock()
	if previous.tenantTLS != nil {
		_ = previous.tenantTLS.Close()
	}
	return nil
}

func (l *Listener) renew(ctx context.Context) error {
	l.mu.Lock()
	accessToken := l.lease.accessToken
	l.mu.Unlock()

	resp, err := l.control.Renew(ctx, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(leaseTTL / time.Second),
	})
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lease.accessToken != accessToken {
		return errors.New("lease changed during renewal")
	}
	l.lease.accessToken = resp.AccessToken
	l.lease.reverse = resp.ReverseEndpoint
	l.lease.expiresAt = resp.ExpiresAt
	l.lease.tenantTLS.SetAccessToken(resp.AccessToken)
	return nil
}

// reverseTarget reads where a reverse connection goes and the capability it presents,
// from the lease as it stands now.
func (l *Listener) reverseTarget() (*url.URL, string, error) {
	l.mu.Lock()
	reverse := l.lease.reverse
	l.mu.Unlock()
	if !reverse.ExpiresAt.After(time.Now()) {
		return nil, "", errors.New("reverse capability expired")
	}
	target, err := url.Parse(reverse.URL)
	if err != nil {
		return nil, "", err
	}
	return target, reverse.Capability, nil
}

func staleLease(err error) bool {
	return errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) ||
		errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeUnauthorized})
}

// reverseCarrier is the WebSocket one run of a lease shares among its reverse
// connections. It dials on first use and again if the WebSocket drops.
type reverseCarrier struct {
	listener *Listener

	mu     sync.Mutex
	mux    *transport.ReverseMux
	closed bool
}

func (c *reverseCarrier) Open(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, net.ErrClosed
	}
	if c.mux == nil || ended(c.mux) {
		target, capability, err := c.listener.reverseTarget()
		if err != nil {
			return nil, err
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		mux, err := transport.DialReverseMux(handshakeCtx, target, capability)
		cancel()
		if err != nil {
			return nil, err
		}
		c.mux = mux
	}
	return c.mux.Open()
}

func (c *reverseCarrier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	if c.mux == nil {
		return nil
	}
	return c.mux.Close()
}

func ended(mux *transport.ReverseMux) bool {
	select {
	case <-mux.Done():
		return true
	default:
		return false
	}
}
