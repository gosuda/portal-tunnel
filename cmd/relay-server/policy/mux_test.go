package policy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestMuxRejectsMethodBeforeAdmission(t *testing.T) {
	for _, path := range []string{types.PathSDKRegisterChallenge, types.PathSDKRegister, types.PathDiscoveryAnnounce} {
		t.Run(path, func(t *testing.T) {
			limiter := NewSourceLimiter(60, 1, 0, 0)
			handler := Mux(nil, http.NotFoundHandler(), nil, limiter, nil, types.PreAuthConfig{
				ChallengeCost: 1,
				RegisterCost:  1,
				AnnounceCost:  1,
			})
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("GET status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
			}
			if retry, _ := limiter.Allow(netip.MustParseAddr("192.0.2.1"), 1); retry != 0 {
				t.Fatal("unsupported method consumed the pre-auth budget")
			}
		})
	}
}

func TestMuxLeavesFallbackBodyLimitsToOwner(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := Mux(nil, fallback, nil, nil, nil, types.PreAuthConfig{})
	request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("upload"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("fallback status = %d, want 201", response.Code)
	}
}
