package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

type ListenerConfig struct {
	Identity         types.Identity
	UDPEnabled       bool
	TCPEnabled       bool
	BanMITM          bool
	Metadata         types.LeaseMetadata
	RootCAPEM        []byte
	DialTimeout      time.Duration
	RequestTimeout   time.Duration
	HandshakeTimeout time.Duration
	LeaseTTL         time.Duration
	RenewBefore      time.Duration
	ReadyTarget      int
	RetryCount       int
	RetryWait        time.Duration
	relaySet         *discovery.RelaySet
}

type Listener struct {
	api    *apiClient
	cancel context.CancelFunc
	doneCh <-chan struct{}

	retryCount  int
	retryWait   time.Duration
	leaseTTL    time.Duration
	renewBefore time.Duration

	stream      *transport.ClientStream
	datagram    *transport.ClientDatagram
	mitmManager *mitmManager

	registered   chan struct{}
	closeOnce    sync.Once
	registerOnce sync.Once

	banMITM    bool
	tcpEnabled bool
	identity   types.Identity
	relaySet   *discovery.RelaySet
	mu         sync.Mutex
	hostname   string
	udpAddr    string
	metadata   types.LeaseMetadata
	tlsConfig  *tls.Config
	tlsCloser  io.Closer
}

// NewListener creates one relay listener and its dedicated relay transport for one relay URL.
// Only local config validation fails immediately; relay startup runs in the background until ready.
func NewListener(ctx context.Context, relayURL string, cfg ListenerConfig) (*Listener, error) {
	listenerCtx, cancel := context.WithCancel(ctx)
	readyTarget := utils.IntOrDefault(cfg.ReadyTarget, defaultReadyTarget)
	leaseTTL := utils.DurationOrDefault(cfg.LeaseTTL, defaultLeaseTTL)
	handshakeTimeout := utils.DurationOrDefault(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	renewBefore := utils.DurationOrDefault(cfg.RenewBefore, defaultRenewBefore)
	retryWait := utils.DurationOrDefault(cfg.RetryWait, defaultRetryWait)

	api, err := newApiClient(relayURL, cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	l := &Listener{
		doneCh:      listenerCtx.Done(),
		cancel:      cancel,
		api:         api,
		registered:  make(chan struct{}),
		retryCount:  cfg.RetryCount,
		retryWait:   retryWait,
		leaseTTL:    leaseTTL,
		renewBefore: renewBefore,
		identity:    api.identity.Copy(),
		metadata:    cfg.Metadata.Copy(),
		banMITM:     cfg.BanMITM,
		tcpEnabled:  cfg.TCPEnabled,
		relaySet:    cfg.relaySet,
	}
	l.mitmManager = newMITMManager(listenerCtx, l)
	l.stream = transport.NewClientStream(readyTarget, handshakeTimeout)
	if cfg.UDPEnabled {
		l.datagram = transport.NewClientDatagram(func(err error) {
			log.Info().
				Err(err).
				Str("component", "sdk-datagram-plane").
				Str("address", l.Address()).
				Msg("quic datagram plane disconnected; waiting to reconnect")
		})
		go l.datagram.RunLoop(listenerCtx, l.currentDatagramState, func(ctx context.Context, state transport.ClientDatagramState) (*quic.Conn, error) {
			return l.api.openQUICSession(ctx, state.AccessToken)
		})
	}

	go l.runStartup(listenerCtx, readyTarget)
	return l, nil
}

func (l *Listener) runStartup(ctx context.Context, readyTarget int) {
	var retries int

	for {
		err := l.registerAndConfigure(ctx)
		switch {
		case err == nil:
			for range readyTarget {
				go l.stream.RunLoop(
					ctx,
					func(ctx context.Context) (net.Conn, error) {
						return l.api.openReverseSession(ctx)
					},
					func() *tls.Config {
						l.mu.Lock()
						defer l.mu.Unlock()
						return l.tlsConfig
					},
					l.retryOrClose,
				)
			}
			go l.runRenewLoop(ctx)
			publicURL := l.PublicURL()
			event := log.Info().Str("address", l.Address())
			if publicURL != "" {
				event.
					Msg("service ready at " + publicURL)
				return
			}
			event.Msg("relay listener registered")
			return
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			return
		default:
			if errors.Is(err, errRelayIncompatible) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeFeatureUnavailable}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeTransportMismatch}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeHostnameConflict}) ||
				errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeIPBanned}) {
				log.Error().
					Err(err).
					Str("relay_url", l.api.baseURL.String()).
					Str("address", l.Address()).
					Msg("lease registration failed; closing listener")
				_ = l.Close()
				return
			}
			retries++
			if !l.retryOrClose(ctx, "lease registration", err, retries) {
				return
			}
		}
	}
}

func (l *Listener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}

		l.mu.Lock()
		identity := l.identity.Copy()
		registered := l.hostname != ""
		tlsCloser := l.tlsCloser
		stream := l.stream
		datagram := l.datagram
		api := l.api
		l.hostname = ""
		l.udpAddr = ""
		l.tlsConfig = nil
		l.tlsCloser = nil
		l.mu.Unlock()

		if l.mitmManager != nil {
			l.mitmManager.reset()
		}

		if stream != nil {
			stream.Drain()
		}
		if datagram != nil {
			datagram.Close()
		}

		if api != nil && registered && identity.Key() != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			closeErr = errors.Join(closeErr, api.unregisterLease(ctx))
			cancel()
		}
		if tlsCloser != nil {
			closeErr = errors.Join(closeErr, tlsCloser.Close())
		}
		if api != nil {
			api.close()
		}
	})
	return closeErr
}

func (l *Listener) Accept() (net.Conn, error) {
	if l.stream == nil {
		return nil, net.ErrClosed
	}
	for {
		conn, err := l.stream.Accept(l.doneCh)
		if err != nil {
			return nil, err
		}

		nextConn, handled, handleErr := l.mitmManager.maybeHandleConn(conn)
		if handleErr != nil {
			log.Debug().
				Err(handleErr).
				Str("relay_url", l.api.baseURL.String()).
				Str("address", l.Address()).
				Msg("mitm self-probe handling failed")
		}
		if handled {
			continue
		}
		return wrapMITMProbeConn(l.mitmManager, nextConn), nil
	}
}

func (l *Listener) AcceptDatagram() (types.DatagramFrame, error) {
	if l == nil || l.datagram == nil {
		return types.DatagramFrame{}, net.ErrClosed
	}

	frame, err := l.datagram.Accept(l.doneCh)
	if err != nil {
		return types.DatagramFrame{}, err
	}

	frame.Payload = append([]byte(nil), frame.Payload...)
	l.mu.Lock()
	frame.Address = l.identity.Address
	frame.UDPAddr = l.udpAddr
	if l.api != nil && l.api.baseURL != nil {
		frame.RelayURL = l.api.baseURL.String()
	}
	l.mu.Unlock()
	return frame, nil
}

func (l *Listener) SendDatagram(frame types.DatagramFrame) error {
	if l == nil || l.datagram == nil {
		return net.ErrClosed
	}

	l.mu.Lock()
	datagram := l.datagram
	address := l.identity.Address
	l.mu.Unlock()

	if address == "" || datagram == nil {
		return net.ErrClosed
	}
	if frameAddress := strings.TrimSpace(frame.Address); frameAddress != "" && frameAddress != address {
		return errors.New("datagram frame targets stale address")
	}
	return datagram.Send(frame.FlowID, frame.Payload)
}

func (l *Listener) DatagramReady() (string, bool, bool) {
	if l == nil || l.datagram == nil {
		return "", false, false
	}

	l.mu.Lock()
	udpAddr := l.udpAddr
	datagram := l.datagram
	l.mu.Unlock()

	ready := datagram != nil && datagram.Connected() && udpAddr != ""
	select {
	case <-l.registered:
		return udpAddr, ready, udpAddr != "" && !ready
	default:
		return udpAddr, ready, !l.closed()
	}
}

func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.identity.Address == "" {
		return listenerAddr("portal:closed")
	}
	return listenerAddr("portal:" + l.identity.Address)
}

func (l *Listener) Address() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.identity.Address
}

func (l *Listener) Hostname() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hostname
}

func (l *Listener) Metadata() types.LeaseMetadata {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.metadata.Copy()
}

func (l *Listener) Identity() types.Identity {
	if l == nil {
		return types.Identity{}
	}
	return l.identity.Copy()
}

func (l *Listener) PublicURL() string {
	if l == nil || l.api == nil || l.api.baseURL == nil {
		return ""
	}

	l.mu.Lock()
	hostname := l.hostname
	l.mu.Unlock()

	if hostname == "" {
		return ""
	}

	if l.api.baseURL.Scheme == "" {
		return "https://" + hostname
	}

	host := hostname
	if port := l.api.baseURL.Port(); port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	return (&url.URL{
		Scheme: l.api.baseURL.Scheme,
		Host:   host,
	}).String()
}

func (l *Listener) currentDatagramState() (transport.ClientDatagramState, bool) {
	if l.datagram == nil {
		return transport.ClientDatagramState{}, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.api == nil || l.identity.Key() == "" || l.udpAddr == "" {
		return transport.ClientDatagramState{}, false
	}
	l.api.mu.RLock()
	accessToken := l.api.accessToken
	l.api.mu.RUnlock()

	return transport.ClientDatagramState{
		Identity:    l.identity.Copy(),
		AccessToken: accessToken,
	}, true
}

func (l *Listener) runRenewLoop(ctx context.Context) {
	interval := l.leaseTTL / 2
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if l.renewBefore > 0 && l.leaseTTL > l.renewBefore {
		interval = l.leaseTTL - l.renewBefore
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}

	for {
		if !utils.SleepOrDone(ctx, interval) {
			return
		}

		var retries int
		for {
			err := l.renewLease(ctx)
			if err == nil {
				break
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}

			retries++
			if !l.retryOrClose(ctx, "lease renewal", err, retries) {
				return
			}
		}
	}
}

func (l *Listener) renewLease(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := l.api.renewLease(requestCtx, l.leaseTTL)
	cancel()
	if err == nil {
		return nil
	}
	if !errors.Is(err, &types.APIRequestError{Code: types.APIErrorCodeLeaseNotFound}) {
		return err
	}

	requestCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := l.registerAndConfigure(requestCtx); err != nil {
		return err
	}
	return nil
}

func (l *Listener) registerAndConfigure(ctx context.Context) error {
	resp, err := l.api.registerLease(ctx, l.leaseTTL, l.datagram != nil, l.tcpEnabled)
	if err != nil {
		return err
	}
	if l.datagram != nil && !resp.UDPEnabled {
		_ = l.api.unregisterLease(context.Background())
		return &types.APIRequestError{
			Code:    types.APIErrorCodeFeatureUnavailable,
			Message: "relay did not enable required udp support",
		}
	}
	tlsConf, tlsCloser, err := keyless.BuildClientTLSConfig(l.api.baseURL.String(), []string{resp.Hostname}, nil)
	if err != nil {
		_ = l.api.unregisterLease(context.Background())
		return err
	}

	if ctx.Err() != nil {
		_ = l.api.unregisterLease(context.Background())
		if tlsCloser != nil {
			_ = tlsCloser.Close()
		}
		return ctx.Err()
	}

	l.mu.Lock()
	if ctx.Err() != nil {
		l.mu.Unlock()
		_ = l.api.unregisterLease(context.Background())
		if tlsCloser != nil {
			_ = tlsCloser.Close()
		}
		return ctx.Err()
	}
	oldCloser := l.tlsCloser
	datagram := l.datagram
	l.identity.Name = resp.Identity.Name
	l.identity.Address = resp.Identity.Address
	l.hostname = resp.Hostname
	l.udpAddr = resp.UDPAddr
	l.tlsConfig = tlsConf
	l.tlsCloser = tlsCloser
	l.mu.Unlock()

	if oldCloser != nil {
		_ = oldCloser.Close()
	}
	if datagram != nil {
		datagram.Clear("lease updated")
	}
	l.registerOnce.Do(func() { close(l.registered) })
	return nil
}

func (l *Listener) retryOrClose(ctx context.Context, operation string, err error, retries int) bool {
	if ctx.Err() != nil {
		return false
	}

	logger := log.With().
		Str("relay_url", l.api.baseURL.String()).
		Str("operation", operation).
		Str("address", l.Address()).
		Logger()

	if l.retryCount > 0 && retries > l.retryCount {
		if operation != "lease renewal" {
			logger.Error().
				Err(err).
				Int("retry_count", l.retryCount).
				Msg("retry budget exhausted; closing listener")
		}
		_ = l.Close()
		return false
	}

	if operation != "lease renewal" {
		logger.Debug().
			Err(err).
			Int("retry_attempt", retries).
			Int("retry_count", l.retryCount).
			Dur("retry_wait", l.retryWait).
			Msg("operation failed; retrying")
	}

	return utils.SleepOrDone(ctx, l.retryWait)
}

type listenerAddr string

func (a listenerAddr) Network() string { return "portal" }
func (a listenerAddr) String() string  { return string(a) }

func (l *Listener) closed() bool {
	select {
	case <-l.doneCh:
		return true
	default:
		return false
	}
}

func (l *Listener) ban() {
	if l.relaySet != nil && l.api != nil && l.api.baseURL != nil {
		l.relaySet.BanRelayURL(l.api.baseURL.String())
	}
	_ = l.Close()
}

func (l *Listener) BanMITM() bool {
	if l == nil {
		return false
	}
	return l.banMITM
}
