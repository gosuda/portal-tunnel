package policy

import (
	"math"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const accessPublishAttempts = 8

type sourceHandler func(http.ResponseWriter, *http.Request, netip.Addr)

func publishServiceAccess(s *portal.Server, access *Store, key types.ServiceIdentityKey) bool {
	if !key.Valid() {
		return true
	}
	if access == nil {
		return s.SetServiceIdentityAccess(key, types.LeaseRoutable, 1)
	}
	for range accessPublishAttempts {
		state := access.Snapshot()
		if s.SetServiceIdentityAccess(key, state.Access(key), state.Revision()) {
			return true
		}
	}
	return false
}

func admitPreAuth(admission *SourceLimiter, ingress *Ingress, cost int, next sourceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := ingress.SourceAddr(r)
		if admission != nil {
			retry, _ := admission.Allow(source, cost)
			if retry > 0 {
				WriteRetryAfter(w, retry, "pre-auth request budget exhausted")
				return
			}
		}
		next(w, r, source)
	}
}

func requireHTTPMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !utils.RequireMethod(w, r, method) {
			return
		}
		next(w, r)
	}
}

func withRequestSource(ingress *Ingress, next sourceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r, ingress.SourceAddr(r))
	}
}

func requireTunnelSource(ingress *Ingress, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := ingress.SourceAddr(r)
		if !ingress.allowsTunnelFrom(source) {
			from := "an unresolved address"
			if source.IsValid() {
				from = source.String()
			}
			utils.WriteAPIError(w, http.StatusForbidden, types.APIErrorCodeSourceNotAllowed, "this relay does not accept tunnels from "+from)
			return
		}
		next(w, r)
	}
}

func reportAccessPublishFailure(w http.ResponseWriter, ok bool, published bool) bool {
	if published {
		return false
	}
	if ok {
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "access decision could not be published")
	}
	return true
}

func controlCORS(mux *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Access-Control-Allow-Origin", "*")
		header.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, DELETE, OPTIONS")
		header.Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, "+types.HeaderAccessToken)
		header.Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	}
}

func guardedRelayRoutes(guarded, control http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		escapedPath := r.URL.EscapedPath()
		cleanPath := path.Clean(escapedPath)
		if strings.HasSuffix(escapedPath, "/") && cleanPath != "/" {
			cleanPath += "/"
		}
		if r.Method != http.MethodConnect && escapedPath != cleanPath {
			guarded.ServeHTTP(w, r)
			return
		}
		requestPath := path.Clean(r.URL.Path)
		for _, prefix := range []string{types.PathSDKPrefix, types.PathDiscovery, types.PathV1Prefix} {
			if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
				guarded.ServeHTTP(w, r)
				return
			}
		}
		if requestPath == types.PathHealthz || r.Method == http.MethodOptions {
			guarded.ServeHTTP(w, r)
			return
		}
		control.ServeHTTP(w, r)
	}
}

func registerDirectRelayRoutes(mux *http.ServeMux, s *portal.Server, fallback http.Handler, ingress *Ingress) {
	mux.HandleFunc(types.PathHealthz, func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc(types.PathSDKDomain, func(w http.ResponseWriter, r *http.Request) {
		if s.ApplicationOwnsDomainReport() {
			fallback.ServeHTTP(w, r)
			return
		}
		s.HandleDomain(w, r)
	})
	mux.HandleFunc(types.PathSDKCertificateChain, s.HandleCertificateChain)
	mux.HandleFunc(types.PathSDKRenew, requireTunnelSource(ingress, withRequestSource(ingress, s.HandleRenew)))
	mux.HandleFunc(types.PathSDKReverse, s.HandleReverseEndpoint)
	mux.HandleFunc(types.PathSDKUnregister, s.HandleUnregister)
	mux.HandleFunc(types.PathSDKConnect, withRequestSource(ingress, s.HandleConnect))
	mux.HandleFunc(types.PathSDKCache, s.HandleStaticCache)
	mux.HandleFunc(types.PathV1Sign, s.HandleSign)
	// Certificate orders have a separate budget from routine lease traffic:
	// at most two orders per source burst and ten globally, replenished slowly.
	tenantOrders := NewSourceLimiter(1, 2, 2, 10)
	mux.HandleFunc(types.PathV1TenantCertificate, requireHTTPMethod(http.MethodPost, requireTunnelSource(ingress, func(w http.ResponseWriter, r *http.Request) {
		if retry, _ := tenantOrders.Allow(ingress.SourceAddr(r), 1); retry > 0 {
			WriteRetryAfter(w, retry, "tenant certificate issuance budget exhausted")
			return
		}
		s.HandleTenantCertificate(w, r)
	})))
	mux.HandleFunc(types.PathDiscovery, func(w http.ResponseWriter, r *http.Request) {
		if !s.DiscoveryEnabled() {
			fallback.ServeHTTP(w, r)
			return
		}
		s.HandleRelayDiscovery(w, r)
	})
}

// Mux composes the relay's protocol route table over portal handlers with
// ingress client-IP resolution and weighted pre-auth admission; other paths
// fall through to the fallback handler. Nil ingress, admission, or access
// disable their layer.
func handleMuxRelayChallenge(s *portal.Server, access *Store) sourceHandler {
	return func(w http.ResponseWriter, r *http.Request, source netip.Addr) {
		key, response, ok := s.HandleRegisterChallenge(w, r, source)
		if reportAccessPublishFailure(w, ok, publishServiceAccess(s, access, key)) {
			return
		}
		if ok && !s.RefuseChallengeOverBudget(w, key, response.ChallengeID, source) {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	}
}

func handleMuxRelayRegister(s *portal.Server, access *Store) sourceHandler {
	return func(w http.ResponseWriter, r *http.Request, _ netip.Addr) {
		key, response, ok := s.HandleRegister(w, r)
		if reportAccessPublishFailure(w, ok, publishServiceAccess(s, access, key)) {
			return
		}
		if ok {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	}
}

func Mux(s *portal.Server, fallback http.Handler, ingress *Ingress, admission *SourceLimiter, access *Store, preAuth PreAuthConfig) http.Handler {
	if ingress == nil {
		ingress = &Ingress{}
	}
	if fallback == nil {
		root := http.NewServeMux()
		root.HandleFunc("/{$}", s.HandleRoot)
		fallback = ControlBodyHandler(root)
	}
	mux := http.NewServeMux()
	registerDirectRelayRoutes(mux, s, fallback, ingress)
	mux.HandleFunc(types.PathSDKRegisterChallenge, requireHTTPMethod(http.MethodPost, requireTunnelSource(ingress, admitPreAuth(admission, ingress, preAuth.ChallengeCost, handleMuxRelayChallenge(s, access)))))
	mux.HandleFunc(types.PathSDKRegister, requireHTTPMethod(http.MethodPost, requireTunnelSource(ingress, admitPreAuth(admission, ingress, preAuth.RegisterCost, handleMuxRelayRegister(s, access)))))
	mux.HandleFunc(types.PathDiscoveryAnnounce, requireHTTPMethod(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if !s.DiscoveryEnabled() {
			fallback.ServeHTTP(w, r)
			return
		}
		admitPreAuth(admission, ingress, preAuth.AnnounceCost, s.HandleRelayDiscoveryAnnounce).ServeHTTP(w, r)
	}))
	mux.Handle("/", fallback)
	control := controlCORS(mux)
	guarded := ControlBodyHandler(control)
	return guardedRelayRoutes(guarded, control)
}

// WriteRetryAfter answers a rejected admission with the limiter's retry
// guidance and a bounded layer label; no IP history is exposed.
func WriteRetryAfter(w http.ResponseWriter, retry time.Duration, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, message)
}
