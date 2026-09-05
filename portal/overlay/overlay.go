// Package overlay owns authenticated Portal exchanges over an IVNP destination.
package overlay

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const requestTimeout = 45 * time.Second

var errCapacity = errors.New("IVNP connection limit reached")

type network interface {
	DialI2P(context.Context, string) (net.Conn, error)
}

// Runtime owns one destination and all of its accepted and outbound streams.
// Admission stays with the Portal relay catalog; I2P proves destination ownership.
type Runtime struct {
	network     network
	listener    net.Listener
	destination string
	release     func() error
	self        func() (types.RelayDescriptor, error)
	admit       func(types.RelayDescriptor) error
	ctx         context.Context
	handler     http.Handler
	mu          sync.Mutex
	conns       map[*trackedConn]struct{}
	closed      bool
}

func New(ctx context.Context, configPath string, self func() (types.RelayDescriptor, error), admit func(types.RelayDescriptor) error, handler http.Handler) (*Runtime, error) {
	network, listener, destination, release, err := startIVNP(ctx, configPath)
	if err != nil {
		return nil, err
	}
	return NewWithTransport(ctx, network, listener, destination, release, self, admit, handler), nil
}

// NewWithTransport constructs a runtime around an explicit transport boundary.
// It is useful for alternate IVNP implementations and deterministic tests.
func NewWithTransport(ctx context.Context, network network, listener net.Listener, destination string, release func() error, self func() (types.RelayDescriptor, error), admit func(types.RelayDescriptor) error, handler http.Handler) *Runtime {
	return &Runtime{ctx: ctx, handler: handler, network: network, listener: listener, destination: destination, release: release, self: self, admit: admit, conns: make(map[*trackedConn]struct{})}
}

func (o *Runtime) Destination() string { return o.destination }

func (o *Runtime) Serve() error {
	server := &http.Server{Handler: http.HandlerFunc(o.serveHTTP), ReadHeaderTimeout: requestTimeout, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return o.ctx }}
	err := server.Serve(o)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Accept implements the listener used by the HTTP server, so hijacked streams
// remain owned by the runtime and are also closed during shutdown.
func (o *Runtime) Accept() (net.Conn, error) {
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			return nil, err
		}
		tracked, err := o.track(conn)
		if errors.Is(err, errCapacity) {
			continue
		}
		return tracked, err
	}
}
func (o *Runtime) Addr() net.Addr { return o.listener.Addr() }

func (o *Runtime) track(conn net.Conn) (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if len(o.conns) >= 256 {
		_ = conn.Close()
		return nil, errCapacity
	}
	tracked := &trackedConn{Conn: conn, owner: o}
	o.conns[tracked] = struct{}{}
	return tracked, nil
}

func (o *Runtime) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	conns := make([]*trackedConn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	o.mu.Unlock()
	err := o.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return errors.Join(err, o.release())
}

type trackedConn struct {
	net.Conn
	owner *Runtime
}

func (c *trackedConn) Close() error {
	c.owner.mu.Lock()
	delete(c.owner.conns, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func matchesDestination(address, destination string) bool {
	host, _, err := net.SplitHostPort(address)
	return err == nil && destination != "" && host == destination
}

// exchange authenticates both Portal identities against the I2P stream's
// cryptographically authenticated endpoints. It never follows HTTP redirects.
func (o *Runtime) exchange(ctx context.Context, peer types.RelayDescriptor, method, path, token string) (net.Conn, *http.Response, error) {
	if err := o.admit(peer); err != nil {
		return nil, nil, err
	}
	if peer.IVNPDestination == "" {
		return nil, nil, errors.New("relay has no IVNP destination")
	}
	local, err := o.self()
	if err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(local)
	if err != nil {
		return nil, nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	conn, err := o.network.DialI2P(dialCtx, net.JoinHostPort(peer.IVNPDestination, types.RelayOverlayPort))
	if err != nil {
		return nil, nil, err
	}
	conn, err = o.track(conn)
	if err != nil {
		return nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if !matchesDestination(conn.RemoteAddr().String(), peer.IVNPDestination) {
		return nil, nil, errors.New("IVNP peer destination mismatch")
	}
	deadline, _ := dialCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	defer stop()
	req := &http.Request{Method: method, URL: &url.URL{Scheme: "http", Host: net.JoinHostPort(peer.IVNPDestination, types.RelayOverlayPort), Path: path}, Header: make(http.Header)}
	req.Header.Set(types.HeaderRelayDescriptor, base64.RawURLEncoding.EncodeToString(raw))
	req.Header.Set(types.HeaderAccessToken, token)
	if err := req.Write(conn); err != nil {
		return nil, nil, err
	}
	header := &io.LimitedReader{R: conn, N: 16 << 10}
	reader := bufio.NewReaderSize(header, 4096)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, nil, err
	}
	if header.N == 0 {
		return nil, nil, errors.New("relay response headers too large")
	}
	header.N = math.MaxInt64
	encoded := resp.Header.Get(types.HeaderRelayDescriptor)
	if len(encoded) > 8192 {
		return nil, nil, errors.New("relay response descriptor too large")
	}
	raw, err = base64.RawURLEncoding.DecodeString(encoded)
	var remote types.RelayDescriptor
	if err != nil || json.Unmarshal(raw, &remote) != nil || remote.Address != peer.Address || remote.APIHTTPSAddr != peer.APIHTTPSAddr || remote.IVNPDestination != peer.IVNPDestination || o.admit(remote) != nil {
		return nil, nil, errors.New("relay response authentication failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("relay exchange rejected: %s", resp.Status)
	}
	if !stop() || dialCtx.Err() != nil {
		return nil, nil, context.Canceled
	}
	if method == http.MethodConnect {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return nil, nil, err
		}
	}
	success = true
	return &bufferedConn{Conn: conn, reader: reader}, resp, nil
}

func (o *Runtime) OpenStream(ctx context.Context, peer types.RelayDescriptor, token string) (net.Conn, error) {
	conn, _, err := o.exchange(ctx, peer, http.MethodConnect, types.PathRelayConnect, token)
	return conn, err
}

func (o *Runtime) DiscoverRelay(ctx context.Context, peer types.RelayDescriptor) (types.DiscoveryResponse, error) {
	var envelope types.APIEnvelope[types.DiscoveryResponse]
	err := o.readJSON(ctx, peer, types.PathDiscovery, "", &envelope)
	if err != nil {
		return types.DiscoveryResponse{}, err
	}
	if !envelope.OK || envelope.Error != nil {
		return types.DiscoveryResponse{}, errors.New("relay discovery rejected")
	}
	return envelope.Data, nil
}

func (o *Runtime) InspectLease(ctx context.Context, peer types.RelayDescriptor, token string) (types.RelayLeaseResponse, error) {
	var envelope types.APIEnvelope[types.RelayLeaseResponse]
	err := o.readJSON(ctx, peer, types.PathRelayLease, token, &envelope)
	if err != nil {
		return types.RelayLeaseResponse{}, err
	}
	if !envelope.OK || envelope.Error != nil {
		return types.RelayLeaseResponse{}, errors.New("relay lease rejected")
	}
	return envelope.Data, nil
}

func (o *Runtime) readJSON(ctx context.Context, peer types.RelayDescriptor, path, token string, out any) error {
	conn, resp, err := o.exchange(ctx, peer, http.MethodGet, path, token)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer resp.Body.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (o *Runtime) serveHTTP(w http.ResponseWriter, r *http.Request) {
	encoded := r.Header.Get(types.HeaderRelayDescriptor)
	if len(encoded) > 8192 {
		http.Error(w, "relay descriptor too large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	var peer types.RelayDescriptor
	if err != nil || json.Unmarshal(raw, &peer) != nil || !matchesDestination(r.RemoteAddr, peer.IVNPDestination) || o.admit(peer) != nil {
		http.Error(w, "relay authentication failed", http.StatusForbidden)
		return
	}
	local, err := o.self()
	if err != nil {
		http.Error(w, "relay descriptor unavailable", http.StatusServiceUnavailable)
		return
	}
	raw, err = json.Marshal(local)
	if err != nil {
		http.Error(w, "relay descriptor unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set(types.HeaderRelayDescriptor, base64.RawURLEncoding.EncodeToString(raw))
	o.handler.ServeHTTP(w, r)
}

func (c *trackedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}
func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}
