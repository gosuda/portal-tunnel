package policy

import (
	"net/http"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ControlBodyHandler bounds HTTP/1 control-body reads and closes the connection
// after every request with a body. Cache POST/PUT handlers own their deadlines;
// this handler still terminates unread bodies after their early rejections.
// Apply it only to owned control routes, not arbitrary application uploads.
func ControlBodyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		w.Header().Set("Connection", "close")
		// net/http may drain the original body after the handler returns.
		// Expire reads first, even when the handler rejected before decoding.
		defer func() { _ = controller.SetReadDeadline(time.Now()) }()
		if err := controller.EnableFullDuplex(); err != nil {
			utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "full-duplex request handling unavailable")
			return
		}
		cacheBody := r.URL.Path == types.PathSDKCache && (r.Method == http.MethodPost || r.Method == http.MethodPut)
		if !cacheBody {
			if err := controller.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				utils.WriteAPIError(w, http.StatusServiceUnavailable, types.APIErrorCodeFeatureUnavailable, "request body deadline unavailable")
				return
			}
		}
		// Reverse carriers upgrade bodyless GET requests. Reject an HTTP body
		// before hijacking so cleanup cannot expire a live reverse connection.
		if r.URL.Path == types.PathSDKConnect && r.Method == http.MethodGet {
			utils.WriteAPIError(w, http.StatusBadRequest, types.APIErrorCodeInvalidRequest, "reverse connect must not include a request body")
			return
		}
		next.ServeHTTP(w, r)
	})
}
