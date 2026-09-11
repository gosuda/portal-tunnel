package overlay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

	"github.com/gosuda/portal-tunnel/v2/internal/identity"
	"github.com/gosuda/portal-tunnel/v2/internal/protocol"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	capabilityPrefix        = "ov1"
	streamPort              = "4017"
	capabilityLimit         = 16 << 10
	connectionLimit         = 128
	sourceConnectionLimit   = 16
	sourceRequestsPerMinute = 120
	sourceRequestBurst      = 16
	gatewayRetryDelay       = 30 * time.Second
	minimumGatewayTTL       = 30 * time.Second
	accepted                = byte(1)
	capacity                = byte(2)
)

type Config struct {
	ConfigPath     string
	Authority      identity.Authority
	Descriptors    func() []types.RelayDescriptor
	SelfDescriptor func(time.Time) (types.RelayDescriptor, error)
	OfferReverse   func(identityKey, leaseID string, conn net.Conn, ready func() error) error
	Bridge         func(net.Conn, net.Conn)
}

var ErrLeaseUnavailable = errors.New("overlay ingress lease is unavailable")

// Runtime is the sole owner of IVNP gateway selection, capabilities, framing,
// peer verification, capacity, and connection lifetime.
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
	sourceLimiter *policy.SourceLimiter
	admissionMu   sync.Mutex
	outbound      int
	activeSources map[string]int

	assignmentMu sync.Mutex
	assignments  map[string]string
	failures     map[string]map[string]time.Time
}

func New(config Config) (*Runtime, error) {
	config.ConfigPath = strings.TrimSpace(config.ConfigPath)
	missingCallbacks := config.Descriptors == nil || config.SelfDescriptor == nil || config.OfferReverse == nil || config.Bridge == nil
	if config.ConfigPath == "" || config.Authority == nil || missingCallbacks {
		return nil, errors.New("overlay runtime configuration is incomplete")
	}
	return &Runtime{
		config:        config,
		inbound:       make(chan struct{}, connectionLimit),
		sourceLimiter: policy.NewSourceLimiter(sourceRequestsPerMinute, sourceRequestBurst),
		activeSources: make(map[string]int),
		assignments:   make(map[string]string),
		failures:      make(map[string]map[string]time.Time),
	}, nil
}

func (r *Runtime) Start(ctx context.Context) error {
	if r == nil {
		return errors.New("overlay runtime is unavailable")
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
		return errors.New("IVNP configuration must be a JSON object without runtime Logger or Resolver values")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("IVNP configuration must contain exactly one JSON object")
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
		return errors.New("overlay runtime is not started")
	}
	// Constructor contexts do not own IVNP resources after success. Close the
	// router explicitly to cancel construction and join all destination I/O.
	stop := context.AfterFunc(ctx, r.Close)
	defer stop()
	defer r.Close()
	// NewDestination waits for tunnels and publication; keep it off the public
	// server startup path so an unavailable overlay still permits direct traffic.
	endpoint, err := r.router.NewDestination(r.ctx, ivnp.DefaultDestinationConfig())
	if err != nil {
		if r.ctx.Err() != nil {
			return nil
		}
		return err
	}
	listener, err := endpoint.ListenContext(r.ctx, "i2p", ":"+streamPort)
	if err != nil {
		if r.ctx.Err() != nil {
			return nil
		}
		return err
	}
	r.lifecycleMu.Lock()
	if r.ctx.Err() != nil {
		r.lifecycleMu.Unlock()
		return nil
	}
	r.endpoint = endpoint
	r.ready.Store(true)
	r.lifecycleMu.Unlock()
	defer r.ready.Store(false)
	log.Info().Str("destination", endpoint.B32()).Msg("relay overlay ready")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if r.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if _, err := peerDestination(conn); err != nil {
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

func (r *Runtime) Handles(capability string) bool {
	return strings.HasPrefix(strings.TrimSpace(capability), capabilityPrefix+".")
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

// IssueEndpoint returns false when direct reverse transport should be used.
// failedURL excludes a failed gateway when the SDK requests replacement.
func (r *Runtime) IssueEndpoint(leaseIdentity types.Identity, leaseID string, expiresAt time.Time, failedURL string) (protocol.ReverseEndpoint, bool, error) {
	if r == nil || !r.ready.Load() {
		return protocol.ReverseEndpoint{}, false, nil
	}
	now := time.Now().UTC()
	leaseIdentity, err := identity.NormalizeIdentity(leaseIdentity)
	leaseID = strings.TrimSpace(leaseID)
	if err != nil || leaseID == "" || !expiresAt.After(now) {
		return protocol.ReverseEndpoint{}, false, errors.New("overlay lease is invalid")
	}
	ingress, err := r.config.SelfDescriptor(now)
	if err != nil {
		return protocol.ReverseEndpoint{}, false, err
	}
	ingress, err = identity.VerifyRelayDescriptor(ingress)
	if err != nil {
		return protocol.ReverseEndpoint{}, false, err
	}
	ingressDestination, err := utils.NormalizeIVNPDestination(ingress.IVNPDestination)
	if err != nil || ingressDestination != r.Destination() {
		return protocol.ReverseEndpoint{}, false, errors.New("overlay ingress descriptor is invalid")
	}

	candidates := r.gatewayCandidates(now, ingress.Address, ingressDestination)
	if len(candidates) == 0 {
		return protocol.ReverseEndpoint{}, false, nil
	}
	gateway, ok := r.selectGateway(leaseID, failedURL, candidates, now)
	if !ok {
		return protocol.ReverseEndpoint{}, false, nil
	}
	capabilityExpiry := expiresAt.UTC()
	if ingress.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = ingress.ExpiresAt
	}
	if gateway.ExpiresAt.Before(capabilityExpiry) {
		capabilityExpiry = gateway.ExpiresAt
	}
	claims := capabilityClaims{
		Version:            1,
		LeaseIdentity:      leaseIdentity,
		LeaseID:            leaseID,
		ExpiresAt:          capabilityExpiry,
		Ingress:            ingress,
		GatewayAddress:     gateway.Address,
		GatewayDestination: gateway.IVNPDestination,
	}
	capability, err := signCapability(r.config.Authority, claims)
	if err != nil {
		return protocol.ReverseEndpoint{}, false, err
	}
	gatewayURL, err := url.Parse(gateway.APIHTTPSAddr)
	if err != nil {
		return protocol.ReverseEndpoint{}, false, err
	}
	return protocol.ReverseEndpoint{
		URL:        utils.ResolveAPIURL(gatewayURL, protocol.PathSDKConnect).String(),
		Capability: capability,
		ExpiresAt:  capabilityExpiry,
		Overlay:    true,
	}, true, nil
}

func (r *Runtime) gatewayCandidates(now time.Time, ingressAddress, ingressDestination string) []types.RelayDescriptor {
	var candidates []types.RelayDescriptor
	seenAddresses := make(map[string]struct{})
	seenDestinations := make(map[string]struct{})
	for _, candidate := range r.config.Descriptors() {
		verified, err := identity.VerifyRelayDescriptor(candidate)
		if err != nil || !verified.ExpiresAt.After(now.Add(minimumGatewayTTL)) || strings.EqualFold(verified.Address, ingressAddress) {
			continue
		}
		destination, err := utils.NormalizeIVNPDestination(verified.IVNPDestination)
		if err != nil || destination != verified.IVNPDestination || destination == ingressDestination {
			continue
		}
		addressKey := strings.ToLower(verified.Address)
		if _, ok := seenAddresses[addressKey]; ok {
			continue
		}
		if _, ok := seenDestinations[destination]; ok {
			continue
		}
		seenAddresses[addressKey] = struct{}{}
		seenDestinations[destination] = struct{}{}
		candidates = append(candidates, verified)
	}
	slices.SortFunc(candidates, func(a, b types.RelayDescriptor) int {
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
	})
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
	for origin, retryAt := range failed {
		if !retryAt.After(now) {
			delete(failed, origin)
		}
	}
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

func endpointOrigin(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func (r *Runtime) HandleConnect(w http.ResponseWriter, request *http.Request, capability, clientIP string) {
	if r == nil || !r.ready.Load() {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay is unavailable")
		return
	}
	// The server resolves clientIP using its trusted-proxy policy. Caller-chosen
	// signing keys and lease IDs must not create fresh admission budgets.
	if !r.sourceLimiter.Allow(clientIP) {
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay request rate exceeded")
		return
	}
	claims, err := verifyCapability(capability, time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.GatewayAddress, r.config.Authority.Identity().Address) || claims.GatewayDestination != r.Destination() {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		return
	}
	r.admissionMu.Lock()
	if r.activeSources[clientIP] >= sourceConnectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay source capacity exhausted")
		return
	}
	if r.outbound >= connectionLimit {
		r.admissionMu.Unlock()
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		return
	}
	r.outbound++
	r.activeSources[clientIP]++
	r.admissionMu.Unlock()
	defer func() {
		r.admissionMu.Lock()
		r.outbound--
		r.activeSources[clientIP]--
		if r.activeSources[clientIP] == 0 {
			delete(r.activeSources, clientIP)
		}
		r.admissionMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	upstream, err := r.dial(ctx, claims.Ingress.IVNPDestination)
	cancel()
	if err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return
	}
	defer closeNow(upstream)
	_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
	if err := binary.Write(upstream, binary.BigEndian, uint16(len(capability))); err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return
	}
	if _, err := io.WriteString(upstream, capability); err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return
	}
	var response [1]byte
	if _, err := io.ReadFull(upstream, response[:]); err != nil {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "relay overlay route is unavailable")
		return
	}
	if response[0] == capacity {
		utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, "relay overlay capacity exhausted")
		return
	}
	if response[0] != accepted {
		utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeUnauthorized, "reverse capability is invalid")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		utils.WriteAPIError(w, http.StatusInternalServerError, types.APIErrorCodeHijackUnsupported, "hijacking is not supported")
		return
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer downstream.Close()
	stop := context.AfterFunc(r.ctx, func() { _ = downstream.Close() })
	defer stop()
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	_ = downstream.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	r.config.Bridge(&bufferedConn{Conn: downstream, reader: buffered.Reader}, upstream)
}

func (r *Runtime) acceptReverse(conn net.Conn) {
	acceptedConn := false
	defer func() {
		if !acceptedConn {
			closeNow(conn)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil || size == 0 || int(size) > capabilityLimit {
		return
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return
	}
	peer, err := peerDestination(conn)
	if err != nil {
		_, _ = conn.Write([]byte{0})
		return
	}
	claims, err := verifyCapability(string(raw), time.Now().UTC())
	if err != nil || !strings.EqualFold(claims.Ingress.Address, r.config.Authority.Identity().Address) || claims.Ingress.IVNPDestination != r.Destination() || claims.GatewayDestination != peer {
		_, _ = conn.Write([]byte{0})
		return
	}
	if err := r.config.OfferReverse(claims.LeaseIdentity.Key(), claims.LeaseID, conn, func() error {
		_, err := conn.Write([]byte{accepted})
		return err
	}); err != nil {
		status := capacity
		if errors.Is(err, ErrLeaseUnavailable) {
			status = 0
		}
		_, _ = conn.Write([]byte{status})
		return
	}
	_ = conn.SetDeadline(time.Time{})
	acceptedConn = true
}

func (r *Runtime) dial(ctx context.Context, destination string) (net.Conn, error) {
	if r.endpoint == nil {
		return nil, errors.New("overlay endpoint is unavailable")
	}
	destination, err := utils.NormalizeIVNPDestination(destination)
	if err != nil {
		return nil, err
	}
	conn, err := r.endpoint.DialContext(ctx, "i2p", net.JoinHostPort(destination, streamPort))
	if err != nil {
		return nil, err
	}
	peer, err := peerDestination(conn)
	if err != nil || peer != destination {
		closeNow(conn)
		return nil, errors.New("overlay peer does not match destination")
	}
	return conn, nil
}

type capabilityClaims struct {
	Version            int                   `json:"version"`
	LeaseIdentity      types.Identity        `json:"lease_identity"`
	LeaseID            string                `json:"lease_id"`
	ExpiresAt          time.Time             `json:"expires_at"`
	Ingress            types.RelayDescriptor `json:"ingress"`
	GatewayAddress     string                `json:"gateway_address"`
	GatewayDestination string                `json:"gateway_destination"`
}

func signCapability(authority identity.Authority, claims capabilityClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signature, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		return "", err
	}
	compact, err := signature.Compact()
	if err != nil {
		return "", err
	}
	return capabilityPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(compact), nil
}

func verifyCapability(capability string, now time.Time) (capabilityClaims, error) {
	capability = strings.TrimSpace(capability)
	if len(capability) == 0 || len(capability) > capabilityLimit {
		return capabilityClaims{}, errors.New("invalid overlay capability length")
	}
	parts := strings.Split(capability, ".")
	if len(parts) != 3 || parts[0] != capabilityPrefix {
		return capabilityClaims{}, errors.New("invalid overlay capability")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > capabilityLimit {
		return capabilityClaims{}, errors.New("invalid overlay capability payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return capabilityClaims{}, errors.New("invalid overlay capability signature")
	}
	var claims capabilityClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return capabilityClaims{}, errors.New("invalid overlay capability claims")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return capabilityClaims{}, errors.New("invalid overlay capability claims")
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		return capabilityClaims{}, errors.New("non-canonical overlay capability")
	}
	verifiedIngress, err := identity.VerifyRelayDescriptor(claims.Ingress)
	if err != nil {
		return capabilityClaims{}, err
	}
	verifiedIngress.IVNPDestination, err = utils.NormalizeIVNPDestination(verifiedIngress.IVNPDestination)
	if err != nil {
		return capabilityClaims{}, err
	}
	publicKey, err := identity.RecoverSHA256Secp256k1Compact(payload, signature)
	if err != nil {
		return capabilityClaims{}, err
	}
	address, err := identity.AddressFromCompressedPublicKeyHex(hex.EncodeToString(publicKey.SerializeCompressed()))
	if err != nil || !strings.EqualFold(address, verifiedIngress.Address) {
		return capabilityClaims{}, errors.New("overlay capability signer does not match ingress")
	}
	leaseIdentity, err := identity.NormalizeIdentity(claims.LeaseIdentity)
	if err != nil {
		return capabilityClaims{}, err
	}
	claims.LeaseID = strings.TrimSpace(claims.LeaseID)
	claims.GatewayAddress = strings.TrimSpace(claims.GatewayAddress)
	claims.GatewayDestination, err = utils.NormalizeIVNPDestination(claims.GatewayDestination)
	incomplete := claims.Version != 1 || claims.LeaseID == "" || claims.GatewayAddress == ""
	invalidExpiry := !claims.ExpiresAt.After(now) || claims.ExpiresAt.After(verifiedIngress.ExpiresAt)
	if err != nil || incomplete || invalidExpiry {
		return capabilityClaims{}, errors.New("overlay capability is expired or incomplete")
	}
	claims.LeaseIdentity = leaseIdentity
	claims.Ingress = verifiedIngress
	return claims, nil
}

func peerDestination(conn net.Conn) (string, error) {
	// IVNP stream addresses carry the hash authenticated by its handshake.
	// Require the typed address; a hostname on an arbitrary net.Addr is not proof.
	peer, ok := conn.RemoteAddr().(ivnp.Addr)
	if !ok || peer.Hash == (ivnp.Hash{}) || peer.Port == 0 {
		return "", errors.New("overlay connection lacks peer identity")
	}
	return foundation.B32(peer.Hash), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func closeNow(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now())
	_ = conn.Close()
}
