package policy

import (
	"net/http"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Mux composes the relay's protocol route table: portal handlers mounted
// under their SDK paths and wrapped with ingress client-IP resolution and
// weighted pre-auth admission. Everything else falls through to the caller's
// handler (admin API, x402, application routes). A nil ingress resolves the
// socket peer, a nil admission disables pre-auth budgeting, and a nil access
// keeps every identity routable; the relay binary always supplies real ones.
func Mux(s *portal.Server, fallback http.Handler, ingress *Ingress, admission *utils.SourceLimiter, access *Access, preAuth types.PreAuthConfig) http.Handler {
	if ingress == nil {
		ingress = &Ingress{}
	}
	if fallback == nil {
		// No application handler: the relay answers its own root and 404s
		// everything else, matching the standalone Start(ctx, nil) shape.
		root := http.NewServeMux()
		root.HandleFunc("/{$}", s.HandleRoot)
		fallback = root
	}

	// publish pushes the relay's current routability decision into the portal
	// data path before a lease becomes observable through it.
	publish := func(key string) {
		if key == "" {
			return
		}
		access.Publish(key, s.SetIdentityRoutable)
	}
	// admit spends the weighted pre-auth budget before any decoding or
	// signature work, preserving the source -> global ordering established
	// for anonymous protocol requests. Method validation runs first so a
	// malformed request never consumes budget.
	admit := func(method string, cost int, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !utils.RequireMethod(w, r, method) {
				return
			}
			if admission != nil {
				if retry, _ := admission.Allow(ingress.ClientIP(r), cost); retry > 0 {
					WriteRetryAfter(w, retry, "pre-auth request budget exhausted")
					return
				}
			}
			next(w, r)
		}
	}
	withClient := func(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r, ingress.ClientIP(r))
		}
	}
	// Static config, resolved once instead of per request.
	discoveryEnabled := s != nil && s.DiscoveryEnabled()
	domainOwnedByApp := s != nil && s.ApplicationOwnsDomainReport()

	mux := http.NewServeMux()
	mux.HandleFunc(types.PathHealthz, func(w http.ResponseWriter, _ *http.Request) {
		utils.WriteAPIData(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc(types.PathSDKDomain, func(w http.ResponseWriter, r *http.Request) {
		if domainOwnedByApp {
			fallback.ServeHTTP(w, r)
			return
		}
		s.HandleDomain(w, r)
	})
	mux.HandleFunc(types.PathSDKCertificateChain, s.HandleCertificateChain)
	mux.HandleFunc(types.PathSDKRegisterChallenge, admit(http.MethodPost, preAuth.ChallengeCost, func(w http.ResponseWriter, r *http.Request) {
		publish(s.HandleRegisterChallenge(w, r, ingress.ClientIP(r)))
	}))
	mux.HandleFunc(types.PathSDKRegister, admit(http.MethodPost, preAuth.RegisterCost, func(w http.ResponseWriter, r *http.Request) {
		key, response, ok := s.HandleRegister(w, r, ingress.ClientIP(r))
		publish(key)
		if ok {
			utils.WriteAPIData(w, http.StatusCreated, response)
		}
	}))
	mux.HandleFunc(types.PathSDKRenew, withClient(s.HandleRenew))
	mux.HandleFunc(types.PathSDKReverse, s.HandleReverseEndpoint)
	mux.HandleFunc(types.PathSDKUnregister, s.HandleUnregister)
	mux.HandleFunc(types.PathSDKConnect, withClient(s.HandleConnect))
	mux.HandleFunc(types.PathSDKCache, s.HandleStaticCache)
	mux.HandleFunc(types.PathV1Sign, s.HandleSign)
	mux.HandleFunc(types.PathDiscovery, func(w http.ResponseWriter, r *http.Request) {
		if !discoveryEnabled {
			fallback.ServeHTTP(w, r)
			return
		}
		s.HandleRelayDiscovery(w, r)
	})
	mux.HandleFunc(types.PathDiscoveryAnnounce, func(w http.ResponseWriter, r *http.Request) {
		if !discoveryEnabled {
			fallback.ServeHTTP(w, r)
			return
		}
		admit(http.MethodPost, preAuth.AnnounceCost, withClient(s.HandleRelayDiscoveryAnnounce)).ServeHTTP(w, r)
	})
	mux.Handle("/", fallback)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if utils.HandleAPICORS(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}
