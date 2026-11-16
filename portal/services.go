package portal

import (
	"net/http"
	"strconv"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// HandleServices serves bounded network browsing and identity lookup without
// changing the relay descriptor contract at /discovery.
func (s *Server) HandleServices(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	query := r.URL.Query()
	var address string
	if query.Has("address") || query.Has("name") {
		var err error
		address, err = identity.NormalizeEVMAddress(query.Get("address"))
		if err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "a valid identity address is required for identity lookup")
			return
		}
	}
	var name *string
	if query.Has("name") {
		value := query.Get("name")
		if value != "" {
			var err error
			value, err = namespace.NormalizeServiceName(value)
			if err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid service name")
				return
			}
		}
		name = &value
	}
	w.Header().Set("Cache-Control", "no-store")
	response, err := s.services.Lookup(r.Context(), s.PortalURL(), s.PublicLeases(), address, name)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeRateLimited, err.Error())
		return
	}
	utils.WriteAPIData(w, http.StatusOK, response)
}

// HandleServiceComments exposes anonymous, read-only remote observations.
// Local comments continue to use the relay's own comment API.
func (s *Server) HandleServiceComments(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	query := r.URL.Query()
	address, err := identity.NormalizeEVMAddress(query.Get("address"))
	if err != nil || !query.Has("name") {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "a valid service identity is required")
		return
	}
	name := query.Get("name")
	if name != "" {
		name, err = namespace.NormalizeServiceName(name)
		if err != nil {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid service name")
			return
		}
	}
	var offset int
	if query.Has("offset") {
		offset, err = strconv.Atoi(query.Get("offset"))
		if err != nil || offset < 0 || offset >= types.ServiceCommentMaxOffset {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid comment offset")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	response, err := s.services.Comments(r.Context(), s.PortalURL(), address, name, offset)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeRateLimited, err.Error())
		return
	}
	utils.WriteAPIData(w, http.StatusOK, response)
}
