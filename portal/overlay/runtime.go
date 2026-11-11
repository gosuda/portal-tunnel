package overlay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gosuda.org/ivnp"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

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
