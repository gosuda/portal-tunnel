package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestMuxRejectsMethodBeforeAdmission(t *testing.T) {
	limiter := NewSourceLimiter(60, 1, 0, 0)
	handler := Mux(nil, http.NotFoundHandler(), nil, limiter, nil, types.PreAuthConfig{RegisterCost: 1})
	req := httptest.NewRequest(http.MethodGet, types.PathSDKRegister, nil)
	req.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET register status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if retry, _ := limiter.Allow("192.0.2.1", 1); retry != 0 {
		t.Fatal("unsupported method consumed the pre-auth budget")
	}
}
