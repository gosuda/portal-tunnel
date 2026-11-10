package main

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRelayAPIRequiresPortalServer    = errors.New("relay api requires portal server")
	errRelayAPIRequiresPolicyStore     = errors.New("relay api requires policy store")
	errRelayAPIRequiresPolicyStatePath = errors.New("relay api requires policy state path")
)

//go:embed dist/*
var embeddedDistFS embed.FS

const (
	controlBodyLimit = 1 << 16

	pathReputationVote    = types.PathAPIPrefix + "/reputation/vote"
	reputationFilename    = "reputation.json"
	reputationVoterCookie = "portal_voter"
	commentAuthorCookie   = "portal_comment_author"
)

type RelayAPI struct {
	server               *portal.Server
	metrics              *relayMetrics
	policies             *policy.Store
	ingress              *policy.Ingress
	adminToken           string
	policyStatePath      string
	frontendFS           fs.FS
	frontendCache        sync.Map
	frontendCacheEnabled bool
	reputation           *policy.ReputationStore
	policyWriteMu        sync.Mutex
}

func applyNewRelayAPIInitialPolicy(api *RelayAPI, initialSettings types.PolicySettings) error {
	initial := api.policies.Snapshot()
	initial.UDP, initial.TCPPort = initialSettings.UDP, initialSettings.TCPPort
	if strings.TrimSpace(initialSettings.ApprovalMode) != "" {
		mode, err := policy.ParseMode(initialSettings.ApprovalMode)
		if err != nil {
			return err
		}
		initial.SetMode(mode)
	}
	if err := api.loadPolicyState(initial); err != nil {
		return err
	}
	return nil
}

func openNewRelayAPIStores(frontendDir, policyStatePath string) (fs.FS, *policy.ReputationStore, error) {
	frontendFS, err := resolveFrontendFS(frontendDir)
	if err != nil {
		return nil, nil, err
	}
	reputationStore, err := policy.NewReputationStore(filepath.Join(filepath.Dir(policyStatePath), reputationFilename))
	if err != nil {
		return nil, nil, err
	}
	return frontendFS, reputationStore, nil
}

func NewRelayAPI(server *portal.Server, policies *policy.Store, ingress *policy.Ingress, policyStatePath, adminToken, frontendDir string, initialSettings types.PolicySettings) (*RelayAPI, error) {
	if server == nil {
		return nil, errRelayAPIRequiresPortalServer
	}
	if policies == nil {
		return nil, errRelayAPIRequiresPolicyStore
	}
	policyStatePath = strings.TrimSpace(policyStatePath)
	if policyStatePath == "" {
		return nil, errRelayAPIRequiresPolicyStatePath
	}
	frontendFS, reputationStore, err := openNewRelayAPIStores(frontendDir, policyStatePath)
	if err != nil {
		return nil, err
	}

	api := &RelayAPI{
		server:               server,
		metrics:              newRelayMetrics(server),
		policies:             policies,
		ingress:              ingress,
		adminToken:           strings.TrimSpace(adminToken),
		policyStatePath:      policyStatePath,
		frontendFS:           frontendFS,
		frontendCacheEnabled: strings.TrimSpace(frontendDir) == "",
		reputation:           reputationStore,
	}
	if err := applyNewRelayAPIInitialPolicy(api, initialSettings); err != nil {
		return nil, err
	}

	return api, nil
}

func registerRelayHandlerPolicyRoutes(mux *http.ServeMux, api *RelayAPI) {
	mux.HandleFunc(types.PathLLMs, func(w http.ResponseWriter, r *http.Request) {
		serveLLMs(w, r, api.server.PortalURL())
	})
	mux.HandleFunc(types.PathAdmin, api.serveAdmin)
	mux.HandleFunc(types.PathAdminPrefix, api.serveAdmin)
	mux.HandleFunc(types.PathPolicy, api.servePolicy)
	mux.HandleFunc(types.PathPolicyPrefix, api.servePolicy)
	mux.HandleFunc(types.PathState, api.servePublicState)
	mux.HandleFunc(pathReputationVote, api.serveVote)
	mux.HandleFunc(types.PathComments, api.serveComments)
	mux.HandleFunc(types.PathCommentsVote, api.serveVote)
	mux.HandleFunc(types.PathCommentsDelete, api.deleteComment)
}

func registerRelayHandlerInstallRoutes(mux *http.ServeMux, api *RelayAPI) {
	mux.HandleFunc(types.PathInstallShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), false)
	})
	mux.HandleFunc(types.PathInstallPowerShell, func(w http.ResponseWriter, r *http.Request) {
		serveInstallScript(w, r, api.server.PortalURL(), true)
	})
	mux.HandleFunc(types.PathInstallBinPrefix, serveInstallBinary)
	mux.HandleFunc("/", api.serveFrontend)
}

func (api *RelayAPI) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	registerRelayHandlerPolicyRoutes(mux, api)
	registerRelayHandlerInstallRoutes(mux, api)
	return mux
}
func (api *RelayAPI) servePublicState(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}

	leases := api.server.PublicLeases()
	voterCookieID := ""
	if cookie, err := r.Cookie(reputationVoterCookie); err == nil {
		voterCookieID = cookie.Value
	}
	utils.WriteAPIData(w, http.StatusOK, publicStateResponse{
		PublicStateResponse: types.PublicStateResponse{Leases: leases},
		Reputation:          api.reputation.Summaries(api.reputation.ViewerHashFor(voterCookieID), publicIdentityLeases(leases, api.server)),
	})
}

type publicStateResponse struct {
	types.PublicStateResponse
	Reputation []policy.ReputationSummary `json:"reputation,omitempty"`
}
