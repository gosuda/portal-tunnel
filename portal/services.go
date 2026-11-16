package portal

import (
	"net/http"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/namespace"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// HandleServices adds public-service lookup without changing /discovery.
func (s *Server) HandleServices(w http.ResponseWriter, r *http.Request) {
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	address, err := identity.NormalizeEVMAddress(r.URL.Query().Get("address"))
	if err != nil {
		utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "a valid identity address is required")
		return
	}
	var name *string
	if r.URL.Query().Has("name") {
		value := r.URL.Query().Get("name")
		if value != "" {
			value, err = namespace.NormalizeServiceName(value)
			if err != nil {
				utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "invalid service name")
				return
			}
		}
		name = &value
	}
	w.Header().Set("Cache-Control", "no-store")
	utils.WriteAPIData(w, http.StatusOK, s.services.Lookup(r.Context(), s.PortalURL(), s.PublicLeases(), address, name))
}
