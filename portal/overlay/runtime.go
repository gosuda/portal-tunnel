package overlay

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"gosuda.org/ivnp"
	"gosuda.org/ivnp/foundation"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// HandleConnect verifies a gateway connect request, frames the upstream
// handshake, and returns the hijacked client connection paired with the
// gateway connection for the caller to bridge. It returns nil, nil after
// writing an API error.
func (r *Runtime) HandleConnect(w http.ResponseWriter, request *http.Request, capability string, source netip.Addr) (net.Conn, net.Conn) {
	claims, release, ok := r.admitHandleConnectRequest(w, source, capability)
	if !ok {
		return nil, nil
	}
	handoff := false
	defer func() {
		if !handoff {
			release()
		}
	}()
	downstream, buffered, upstream, ok := r.openHandleConnectBridge(w, request, capability, claims.Ingress.IVNPDestination)
	if !ok {
		return nil, nil
	}
	defer func() {
		if !handoff {
			closeNow(upstream)
		}
	}()
	_ = downstream.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	client := &bufferedConn{Conn: downstream, reader: buffered.Reader, release: release}
	client.stop = context.AfterFunc(r.ctx, func() { _ = client.Close() })
	handoff = true
	return client, upstream
}

func (r *Runtime) admitHandleConnectRequest(w http.ResponseWriter, source netip.Addr, capability string) (capabilityClaims, func(), bool) {
	if r == nil || !r.ready.Load() {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay is unavailable")
		return capabilityClaims{}, nil, false
	}
	if retry := r.sourceLimiter.Allow(source, 1); retry > 0 {
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay request rate exceeded")
		return capabilityClaims{}, nil, false
	}
	claims, err := verifyCapability(capability, time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.GatewayAddress, r.config.Authority.Identity().Address) || claims.GatewayDestination != r.Destination() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		return capabilityClaims{}, nil, false
	}
	r.admissionMu.Lock()
	if r.activeSources[source] >= sourceConnectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay source capacity exhausted")
		return capabilityClaims{}, nil, false
	}
	if r.outbound >= connectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		return capabilityClaims{}, nil, false
	}
	r.outbound++
	r.activeSources[source]++
	r.admissionMu.Unlock()
	release := func() {
		r.admissionMu.Lock()
		r.outbound--
		r.activeSources[source]--
		if r.activeSources[source] == 0 {
			delete(r.activeSources, source)
		}
		r.admissionMu.Unlock()
	}
	return claims, release, true
}

func (r *Runtime) exchangeHandleConnectUpstream(w http.ResponseWriter, request *http.Request, capability string, destination string) (net.Conn, bool) {
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	upstream, err := r.dial(ctx, destination)
	cancel()
	if err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return nil, false
	}
	response, ok := transactHandleConnectHandshake(upstream, capability, w)
	if !ok {
		return nil, false
	}
	switch response[0] {
	case types.OverlayStatusAccepted:
	case types.OverlayStatusCapacity:
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		closeNow(upstream)
		return nil, false
	case types.OverlayStatusPending:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeLeaseRejected, "lease is not approved for routing")
		closeNow(upstream)
		return nil, false
	case types.OverlayStatusDenied:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeLeaseDenied, "lease is denied by the relay")
		closeNow(upstream)
		return nil, false
	default:
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		closeNow(upstream)
		return nil, false
	}
	return upstream, true
}

func transactHandleConnectHandshake(upstream net.Conn, capability string, w http.ResponseWriter) ([1]byte, bool) {
	var response [1]byte
	_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
	handshakeErr := binary.Write(upstream, binary.BigEndian, uint16(len(capability)))
	if handshakeErr == nil {
		_, handshakeErr = io.WriteString(upstream, capability)
	}
	if handshakeErr == nil {
		_, handshakeErr = io.ReadFull(upstream, response[:])
	}
	if handshakeErr != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		closeNow(upstream)
		return response, false
	}
	return response, true
}

func upgradeHandleConnectHijack(buffered *bufio.ReadWriter, downstream net.Conn) bool {
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge upgrade write failed")
		_ = downstream.Close()
		return false
	}
	if err := buffered.Flush(); err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge upgrade flush failed")
		_ = downstream.Close()
		return false
	}
	return true
}

type bufferedConn struct {
	net.Conn
	reader  *bufio.Reader
	stop    func() bool
	release func()
	close   sync.Once
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) Close() error {
	err := c.Conn.Close()
	c.close.Do(func() {
		if c.stop != nil {
			c.stop()
		}
		if c.release != nil {
			c.release()
		}
	})
	return err
}

func acceptHandleConnectHijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, bool) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackUnsupported, "hijacking is not supported")
		return nil, nil, false
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		log.Warn().Err(err).Str("component", "overlay").Msg("gateway bridge hijack failed")
		return nil, nil, false
	}
	if !upgradeHandleConnectHijack(buffered, downstream) {
		return nil, nil, false
	}
	return downstream, buffered, true
}

func (r *Runtime) openHandleConnectBridge(w http.ResponseWriter, request *http.Request, capability string, destination string) (net.Conn, *bufio.ReadWriter, net.Conn, bool) {
	upstream, ok := r.exchangeHandleConnectUpstream(w, request, capability, destination)
	if !ok {
		return nil, nil, nil, false
	}
	downstream, buffered, ok := acceptHandleConnectHijack(w)
	if !ok {
		closeNow(upstream)
		return nil, nil, nil, false
	}
	return downstream, buffered, upstream, true
}

// IssueInput is the complete point-in-time state needed to issue an endpoint.
type IssueInput struct {
	LeaseIdentity types.Identity
	LeaseID       string
	ExpiresAt     time.Time
	FailedURL     string
	Self          types.RelayDescriptor
	Descriptors   []types.RelayDescriptor
}

// IssueEndpoint returns false when direct reverse transport should be used.
// Input carries the caller's current relay-state snapshot; FailedURL excludes
// a failed gateway when the SDK requests replacement.
func (r *Runtime) IssueEndpoint(input IssueInput) (types.ReverseEndpoint, bool, error) {
	if r == nil || !r.ready.Load() {
		return types.ReverseEndpoint{}, false, nil
	}
	now := time.Now().UTC()
	input.LeaseID = strings.TrimSpace(input.LeaseID)
	if input.LeaseID == "" || !input.ExpiresAt.After(now) {
		return types.ReverseEndpoint{}, false, errOverlayLeaseIsInvalid
	}
	ingress, ingressDestination, err := r.checkIssueEndpointIngress(input.Self)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}

	candidates := r.gatewayCandidates(input.Descriptors, now, ingress.Address, ingressDestination)
	if len(candidates) == 0 {
		return types.ReverseEndpoint{}, false, nil
	}
	gateway, ok := r.selectGateway(input.LeaseID, input.FailedURL, candidates, now)
	if !ok {
		return types.ReverseEndpoint{}, false, nil
	}
	return r.assembleIssueEndpointResponse(input, ingress, gateway)
}

func (r *Runtime) gatewayCandidates(descriptors []types.RelayDescriptor, now time.Time, ingressAddress, ingressDestination string) []types.RelayDescriptor {
	var candidates []types.RelayDescriptor
	seenAddresses := make(map[string]struct{})
	seenDestinations := make(map[string]struct{})
	for _, candidate := range descriptors {
		verified, destination, ok := r.gatewayCandidatesVerify(candidate, now, ingressAddress, ingressDestination)
		if !ok {
			continue
		}
		addressKey := strings.ToLower(verified.Address)
		_, addrSeen := seenAddresses[addressKey]
		_, destSeen := seenDestinations[destination]
		if addrSeen || destSeen {
			continue
		}
		seenAddresses[addressKey] = struct{}{}
		seenDestinations[destination] = struct{}{}
		candidates = append(candidates, verified)
	}
	slices.SortFunc(candidates, gatewayCandidatesCompare)
	return candidates
}

func (r *Runtime) selectGateway(leaseID, failedURL string, candidates []types.RelayDescriptor, now time.Time) (types.RelayDescriptor, bool) {
	r.assignmentMu.Lock()
	defer r.assignmentMu.Unlock()
	failed := r.failures[leaseID]
	if failed == nil {
		failed = make(map[string]time.Time)
		r.failures[leaseID] = failed
	}
	selectGatewayPrune(failed, now)
	if origin := endpointOrigin(failedURL); origin != "" {
		failed[origin] = now.Add(gatewayRetryDelay)
	}
	candidates = slices.DeleteFunc(candidates, func(candidate types.RelayDescriptor) bool {
		_, rejected := failed[endpointOrigin(candidate.APIHTTPSAddr)]
		return rejected
	})
	if len(candidates) == 0 {
		delete(r.assignments, leaseID)
		return types.RelayDescriptor{}, false
	}
	return r.selectGatewayAssign(leaseID, failedURL, candidates)
}

func endpointOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func (r *Runtime) checkIssueEndpointIngress(self types.RelayDescriptor) (types.RelayDescriptor, string, error) {
	ingress, err := discovery.VerifyRelayDescriptor(self)
	if err != nil {
		return types.RelayDescriptor{}, "", err
	}
	ingressDestination, err := normalizeIVNPDestination(ingress.IVNPDestination)
	if err != nil || ingressDestination != r.Destination() {
		return types.RelayDescriptor{}, "", errOverlayIngressDescriptorIsInvalid
	}
	return ingress, ingressDestination, nil
}

func (r *Runtime) assembleIssueEndpointResponse(input IssueInput, ingress types.RelayDescriptor, gateway types.RelayDescriptor) (types.ReverseEndpoint, bool, error) {
	capabilityExpiry := input.ExpiresAt.UTC()
	if ingress.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = ingress.ExpiresAt
	}
	if gateway.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = gateway.ExpiresAt
	}
	claims := capabilityClaims{
		Version:            1,
		LeaseIdentity:      input.LeaseIdentity,
		LeaseID:            input.LeaseID,
		ExpiresAt:          capabilityExpiry,
		Ingress:            ingress,
		GatewayAddress:     gateway.Address,
		GatewayDestination: gateway.IVNPDestination,
	}
	capability, err := signCapability(r.config.Authority, claims)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}
	gatewayURL, err := url.Parse(gateway.APIHTTPSAddr)
	if err != nil {
		return types.ReverseEndpoint{}, false, err
	}
	return types.ReverseEndpoint{
		URL:        utils.ResolveAPIURL(gatewayURL, types.PathSDKConnect).String(),
		Capability: capability,
		ExpiresAt:  capabilityExpiry,
		Overlay:    true,
		Gateway:    &gateway,
	}, true, nil
}

func (r *Runtime) gatewayCandidatesVerify(candidate types.RelayDescriptor, now time.Time, ingressAddress, ingressDestination string) (types.RelayDescriptor, string, bool) {
	verified, err := discovery.VerifyRelayDescriptor(candidate)
	if err != nil || !verified.ExpiresAt.After(now.Add(minimumGatewayTTL)) || strings.EqualFold(verified.Address, ingressAddress) {
		return types.RelayDescriptor{}, "", false
	}
	destination, err := normalizeIVNPDestination(verified.IVNPDestination)
	if err != nil || destination != verified.IVNPDestination || destination == ingressDestination {
		return types.RelayDescriptor{}, "", false
	}
	return verified, destination, true
}

func gatewayCandidatesCompare(a, b types.RelayDescriptor) int {
	if a.ActiveConnections < b.ActiveConnections {
		return -1
	}
	if a.ActiveConnections > b.ActiveConnections {
		return 1
	}
	if a.TCPBPS < b.TCPBPS {
		return -1
	}
	if a.TCPBPS > b.TCPBPS {
		return 1
	}
	return strings.Compare(a.APIHTTPSAddr, b.APIHTTPSAddr)
}

func selectGatewayPrune(failed map[string]time.Time, now time.Time) {
	for origin, retryAt := range failed {
		if !retryAt.After(now) {
			delete(failed, origin)
		}
	}
}

func (r *Runtime) selectGatewayAssign(leaseID string, failedURL string, candidates []types.RelayDescriptor) (types.RelayDescriptor, bool) {
	current := r.assignments[leaseID]
	if failedURL == "" {
		for _, candidate := range candidates {
			if strings.EqualFold(candidate.Address, current) {
				return candidate, true
			}
		}
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate.Address, current) {
			continue
		}
		r.assignments[leaseID] = candidate.Address
		return candidate, true
	}
	r.assignments[leaseID] = candidates[0].Address
	return candidates[0], true
}

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

// ReverseOffer is a capability-verified inbound reverse connection awaiting
// portal lease admission. Connection ownership transfers with the offer.
type ReverseOffer struct {
	ServiceIdentity types.ServiceIdentityKey
	LeaseID         string
	conn            net.Conn
}

// Connection returns the connection whose ownership transferred with the offer.
func (o ReverseOffer) Connection() net.Conn { return o.conn }

// Accept writes the accepted status for the reverse-offer protocol.
func (o ReverseOffer) Accept() error {
	_, err := o.respond(types.OverlayStatusAccepted)
	return err
}

// RejectUnavailable writes the unavailable status for the reverse-offer protocol.
func (o ReverseOffer) RejectUnavailable() { _, _ = o.respond(types.OverlayStatusUnavailable) }

// RejectCapacity writes the capacity status for the reverse-offer protocol.
func (o ReverseOffer) RejectCapacity() { _, _ = o.respond(types.OverlayStatusCapacity) }

// RejectPending writes the status of a lease that waits for approval.
func (o ReverseOffer) RejectPending() { _, _ = o.respond(types.OverlayStatusPending) }

// RejectDenied writes the status of a lease the relay denied or banned.
func (o ReverseOffer) RejectDenied() { _, _ = o.respond(types.OverlayStatusDenied) }

// Close releases the connection transferred with the offer.
func (o ReverseOffer) Close() { closeNow(o.conn) }

func (o ReverseOffer) respond(status byte) (int, error) { return o.conn.Write([]byte{status}) }

func (r *Runtime) acceptReverse(conn net.Conn) {
	handoff := false
	defer func() {
		if !handoff {
			closeNow(conn)
		}
	}()
	raw, ok := acceptReverseRead(conn)
	if !ok {
		return
	}
	claims, ok := r.acceptReverseVerify(conn, raw)
	if !ok {
		return
	}
	select {
	case r.offers <- ReverseOffer{ServiceIdentity: claims.LeaseIdentity.ServiceKey(), LeaseID: claims.LeaseID, conn: conn}:
		handoff = true
	case <-r.ctx.Done():
	}
}

func acceptReverseRead(conn net.Conn) ([]byte, bool) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil || size == 0 || int(size) > capabilityLimit {
		return nil, false
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, false
	}
	return raw, true
}

func (r *Runtime) acceptReverseVerify(conn net.Conn, raw []byte) (capabilityClaims, bool) {
	peer, err := peerDestination(conn)
	if err != nil {
		_, _ = conn.Write([]byte{types.OverlayStatusUnavailable})
		return capabilityClaims{}, false
	}
	claims, err := verifyCapability(string(raw), time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.Ingress.Address, r.config.Authority.Identity().Address) || claims.Ingress.IVNPDestination != r.Destination() || claims.GatewayDestination != peer {
		_, _ = conn.Write([]byte{types.OverlayStatusUnavailable})
		return capabilityClaims{}, false
	}
	return claims, true
}

func (r *Runtime) dial(ctx context.Context, destination string) (net.Conn, error) {
	if r.endpoint == nil {
		return nil, errOverlayEndpointIsUnavailable
	}
	destination, err := normalizeIVNPDestination(destination)
	if err != nil {
		return nil, err
	}
	conn, err := r.endpoint.DialContext(ctx, "i2p", net.JoinHostPort(destination, types.OverlayStreamPort))
	if err != nil {
		return nil, err
	}
	peer, err := peerDestination(conn)
	if err != nil || peer != destination {
		closeNow(conn)
		return nil, errOverlayPeerDoesNotMatchDestination
	}
	return conn, nil
}

func peerDestination(conn net.Conn) (string, error) {
	peer, ok := conn.RemoteAddr().(ivnp.Addr)
	if !ok || peer.Hash == (ivnp.Hash{}) || peer.Port == 0 {
		return "", errOverlayConnectionLacksPeerIdentity
	}
	return foundation.B32(peer.Hash), nil
}

func closeNow(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now())
	_ = conn.Close()
}

var (
	errIvnpDestinationMust32ByteB32            = errors.New("ivnp destination must be a 32-byte b32.i2p hash")
	errInvalidIvnpDestinationHash              = errors.New("invalid ivnp destination hash")
	errOverlayRuntimeConfigurationIsIncomplete = errors.New("overlay runtime configuration is incomplete")
	errOverlayRuntimeIsUnavailable             = errors.New("overlay runtime is unavailable")
	errIvnpConfigurationMustJSONObjectWithout  = errors.New("IVNP configuration must be a JSON object without runtime Logger or Resolver values")
	errIvnpConfigurationMustContainExactlyOne  = errors.New("IVNP configuration must contain exactly one JSON object")
	errOverlayRuntimeIsNotStarted              = errors.New("overlay runtime is not started")
	errOverlayLeaseIsInvalid                   = errors.New("overlay lease is invalid")
	errOverlayIngressDescriptorIsInvalid       = errors.New("overlay ingress descriptor is invalid")
	errOverlayEndpointIsUnavailable            = errors.New("overlay endpoint is unavailable")
	errOverlayPeerDoesNotMatchDestination      = errors.New("overlay peer does not match destination")
	errInvalidOverlayCapabilityLength          = errors.New("invalid overlay capability length")
	errInvalidOverlayCapability                = errors.New("invalid overlay capability")
	errInvalidOverlayCapabilityPayload         = errors.New("invalid overlay capability payload")
	errInvalidOverlayCapabilitySignature       = errors.New("invalid overlay capability signature")
	errInvalidOverlayCapabilityClaims          = errors.New("invalid overlay capability claims")
	errNonCanonicalOverlayCapability           = errors.New("non-canonical overlay capability")
	errOverlayCapabilitySignerDoesNotMatch     = errors.New("overlay capability signer does not match ingress")
	errOverlayCapabilityExpiredOrIncomplete    = errors.New("overlay capability is expired or incomplete")
	errOverlayConnectionLacksPeerIdentity      = errors.New("overlay connection lacks peer identity")
)

const (
	capabilityLimit         = 16 << 10
	connectionLimit         = 128
	sourceConnectionLimit   = 16
	sourceRequestsPerMinute = 120
	sourceRequestBurst      = 16
	gatewayRetryDelay       = 30 * time.Second
	minimumGatewayTTL       = 30 * time.Second
)

type Config struct {
	ConfigPath string
	Authority  identity.Authority
}

// Runtime owns IVNP gateway selection, capabilities, framing, peer
// verification, and admission.
type Runtime struct {
	config Config

	ctx         context.Context
	cancel      context.CancelFunc
	router      *ivnp.Router
	lifecycleMu sync.Mutex
	endpoint    interface {
		B32() string
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	ready         atomic.Bool
	close         sync.Once
	inbound       chan struct{}
	offers        chan ReverseOffer
	sourceLimiter *sourceLimiter
	admissionMu   sync.Mutex
	outbound      int
	activeSources map[netip.Addr]int

	assignmentMu sync.Mutex
	assignments  map[string]string
	failures     map[string]map[string]time.Time
}

func New(config Config) (*Runtime, error) {
	config.ConfigPath = strings.TrimSpace(config.ConfigPath)
	if config.ConfigPath == "" || config.Authority == nil {
		return nil, errOverlayRuntimeConfigurationIsIncomplete
	}
	return &Runtime{
		config:        config,
		inbound:       make(chan struct{}, connectionLimit),
		offers:        make(chan ReverseOffer),
		sourceLimiter: newSourceLimiter(sourceRequestsPerMinute, sourceRequestBurst),
		activeSources: make(map[netip.Addr]int),
		assignments:   make(map[string]string),
		failures:      make(map[string]map[string]time.Time),
	}, nil
}

func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.close.Do(func() {
		r.lifecycleMu.Lock()
		r.ready.Store(false)
		if r.cancel != nil {
			r.cancel()
		}
		r.lifecycleMu.Unlock()
		r.assignmentMu.Lock()
		clear(r.assignments)
		clear(r.failures)
		r.assignmentMu.Unlock()
		if r.router != nil {
			_ = r.router.Close()
		}
	})
}

func (r *Runtime) Destination() string {
	if r == nil || !r.ready.Load() || r.endpoint == nil {
		return ""
	}
	return r.endpoint.B32()
}

// ReverseOffers hands off verified reverse connections for portal admission.
// The channel is not closed; consumers stop via their own shutdown context.
func (r *Runtime) ReverseOffers() <-chan ReverseOffer {
	if r == nil {
		return nil
	}
	return r.offers
}

func (r *Runtime) ForgetLease(leaseID string) {
	if r == nil || leaseID == "" {
		return
	}
	r.assignmentMu.Lock()
	delete(r.assignments, leaseID)
	delete(r.failures, leaseID)
	r.assignmentMu.Unlock()
}
