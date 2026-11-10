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

// Mux composes the relay's protocol route table over portal handlers with
// ingress client-IP resolution and weighted pre-auth admission; other paths
// fall through to the fallback handler. Nil ingress, admission, or access
// disable their layer.
func Mux(s *portal.Server, fallback http.Handler, ingress *Ingress, admission *SourceLimiter, access *Store, preAuth PreAuthConfig) http.Handler {
	if ingress == nil {
		ingress = &Ingress{}
	}
	if fallback == nil {
		root := http.NewServeMux()
		root.HandleFunc("/{$}", s.HandleRoot)
		fallback = ControlBodyHandler(root)
	}
	publishAccess := func(key types.ServiceIdentityKey) bool {
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

	type sourceHandler func(http.ResponseWriter, *http.Request, netip.Addr)
	admit := func(cost int, next sourceHandler) http.HandlerFunc {
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
	requireMethod := func(method string, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !utils.RequireMethod(w, r, method) {
				return
			}
			next(w, r)
		}
	}
	withSource := func(next sourceHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r, ingress.SourceAddr(r))
		}
	}
	tunnelSource := func(next http.HandlerFunc) http.HandlerFunc {
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

	mux := http.NewServeMux()
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
	mux.HandleFunc(types.PathSDKRegisterChallenge, requireMethod(http.MethodPost, tunnelSource(admit(preAuth.ChallengeCost, func(w http.ResponseWriter, r *http.Request, source netip.Addr) {
		key, response, ok := s.HandleRegisterChallenge(w, r, source)
		if !publishAccess(key) {
			if ok {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "access decision could not be published")
			}
			return
		}
		if ok && !s.RefuseChallengeOverBudget(w, key, response.ChallengeID, source) {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	}))))
	mux.HandleFunc(types.PathSDKRegister, requireMethod(http.MethodPost, tunnelSource(admit(preAuth.RegisterCost, func(w http.ResponseWriter, r *http.Request, _ netip.Addr) {
		key, response, ok := s.HandleRegister(w, r)
		if !publishAccess(key) {
			if ok {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "access decision could not be published")
			}
			return
		}
		if ok {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	}))))
	mux.HandleFunc(types.PathSDKRenew, tunnelSource(withSource(s.HandleRenew)))
	mux.HandleFunc(types.PathSDKReverse, s.HandleReverseEndpoint)
	mux.HandleFunc(types.PathSDKUnregister, s.HandleUnregister)
	mux.HandleFunc(types.PathSDKConnect, withSource(s.HandleConnect))
	mux.HandleFunc(types.PathSDKCache, s.HandleStaticCache)
	mux.HandleFunc(types.PathV1Sign, s.HandleSign)
	mux.HandleFunc(types.PathDiscovery, func(w http.ResponseWriter, r *http.Request) {
		if !s.DiscoveryEnabled() {
			fallback.ServeHTTP(w, r)
			return
		}
		s.HandleRelayDiscovery(w, r)
	})
	mux.HandleFunc(types.PathDiscoveryAnnounce, requireMethod(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		if !s.DiscoveryEnabled() {
			fallback.ServeHTTP(w, r)
			return
		}
		admit(preAuth.AnnounceCost, s.HandleRelayDiscoveryAnnounce).ServeHTTP(w, r)
	}))
	mux.Handle("/", fallback)

	control := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})
	guarded := ControlBodyHandler(control)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})
}

// WriteRetryAfter answers a rejected admission with the limiter's retry
// guidance and a bounded layer label; no IP history is exposed.
func WriteRetryAfter(w http.ResponseWriter, retry time.Duration, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, message)
}
