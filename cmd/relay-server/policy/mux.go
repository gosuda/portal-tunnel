package policy

import (
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const accessPublishAttempts = 8

// Mux composes the relay's protocol route table: portal handlers mounted
// under their SDK paths and wrapped with ingress client-IP resolution and
// weighted pre-auth admission. Everything else falls through to the caller's
// handler (admin API, x402, application routes). A nil ingress resolves the
// socket peer, a nil admission disables pre-auth budgeting, and a nil access
// keeps every identity routable; the relay binary always supplies real ones.
func Mux(s *portal.Server, fallback http.Handler, ingress *Ingress, admission *SourceLimiter, access *Access, preAuth types.PreAuthConfig) http.Handler {
	if ingress == nil {
		ingress = &Ingress{}
	}
	if fallback == nil {
		// No application handler: the relay answers its own root and 404s
		// everything else, matching the standalone Serve(ctx, nil) shape.
		root := http.NewServeMux()
		root.HandleFunc("/{$}", s.HandleRoot)
		fallback = root
	}
	// A newer committed snapshot may reach Portal while this request is
	// paused. Retry a bounded number of times when Portal rejects the older
	// revision; stale values are never applied, and no relay lock is held
	// across the Portal call.
	publishAccess := func(key types.ServiceIdentityKey) bool {
		if !key.Valid() {
			return true
		}
		if access == nil {
			return s.SetServiceIdentityRoutable(key, true, 1)
		}
		for range accessPublishAttempts {
			state := access.Snapshot()
			if s.SetServiceIdentityRoutable(key, state.Routable(key), state.Revision()) {
				return true
			}
		}
		return false
	}

	// admit spends the weighted pre-auth budget before any decoding or
	// signature work, preserving the source -> global ordering established
	// for anonymous protocol requests.
	type sourceHandler func(http.ResponseWriter, *http.Request, netip.Addr)
	admit := func(cost int, next sourceHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			source := ingress.SourceAddr(r)
			if admission != nil {
				if retry, _ := admission.Allow(source, cost); retry > 0 {
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
	mux.HandleFunc(types.PathSDKRegisterChallenge, requireMethod(http.MethodPost, admit(preAuth.ChallengeCost, func(w http.ResponseWriter, r *http.Request, source netip.Addr) {
		key, response, ok := s.HandleRegisterChallenge(w, r, source)
		if !publishAccess(key) {
			if ok {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "access decision could not be published")
			}
			return
		}
		if ok {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	})))
	mux.HandleFunc(types.PathSDKRegister, requireMethod(http.MethodPost, admit(preAuth.RegisterCost, func(w http.ResponseWriter, r *http.Request, source netip.Addr) {
		key, response, ok := s.HandleRegister(w, r, source)
		if !publishAccess(key) {
			if ok {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeInternal, "access decision could not be published")
			}
			return
		}
		if ok {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	})))
	mux.HandleFunc(types.PathSDKRenew, withSource(s.HandleRenew))
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if utils.HandleAPICORS(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// WriteRetryAfter answers a rejected admission with the limiter's retry
// guidance and a bounded layer label; no IP history is exposed.
func WriteRetryAfter(w http.ResponseWriter, retry time.Duration, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
	utils.WriteAPIError(w, http.StatusTooManyRequests, types.APIErrorCodeRateLimited, message)
}
