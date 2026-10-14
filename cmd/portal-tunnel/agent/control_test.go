package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestControlHandlerRejectsUntrustedHostAndOrigin(t *testing.T) {
	handler := &controlHandler{
		authority:          "127.0.0.1:4018",
		localhostAuthority: "localhost:4018",
	}
	tests := []struct {
		name    string
		host    string
		origins []string
		want    int
	}{
		{name: "bound host without origin", host: "127.0.0.1:4018", want: http.StatusOK},
		{name: "bound host and origin", host: "127.0.0.1:4018", origins: []string{"http://127.0.0.1:4018"}, want: http.StatusOK},
		{name: "localhost alias", host: "localhost:4018", origins: []string{"http://localhost:4018"}, want: http.StatusOK},
		{name: "attacker host", host: "attack.example:4018", want: http.StatusForbidden},
		{name: "attacker host and origin", host: "attack.example:4018", origins: []string{"http://attack.example:4018"}, want: http.StatusForbidden},
		{name: "other loopback port", host: "127.0.0.1:4019", want: http.StatusForbidden},
		{name: "other loopback address", host: "127.0.0.2:4018", want: http.StatusForbidden},
		{name: "other origin", host: "127.0.0.1:4018", origins: []string{"http://attack.example"}, want: http.StatusForbidden},
		{name: "other scheme", host: "127.0.0.1:4018", origins: []string{"https://127.0.0.1:4018"}, want: http.StatusForbidden},
		{name: "null origin", host: "127.0.0.1:4018", origins: []string{"null"}, want: http.StatusForbidden},
		{name: "multiple origins", host: "127.0.0.1:4018", origins: []string{"http://127.0.0.1:4018", "http://attack.example"}, want: http.StatusForbidden},
		{name: "empty origin", host: "127.0.0.1:4018", origins: []string{""}, want: http.StatusForbidden},
		{name: "empty host", host: "", want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, types.PathAgentAuthStatus, nil)
			req.Host = tt.host
			for _, origin := range tt.origins {
				req.Header.Add("Origin", origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestControlHandlerRejectsUntrustedHostBeforeAuthorization(t *testing.T) {
	handler := &controlHandler{
		token:              "secret",
		authority:          "127.0.0.1:4018",
		localhostAuthority: "localhost:4018",
	}
	for _, endpoint := range []struct {
		path   string
		method string
	}{
		{types.PathAgentAuthChallenge, http.MethodPost},
		{types.PathAgentAuthLogin, http.MethodPost},
		{types.PathAgentAuthLogout, http.MethodPost},
		{types.PathAgentAuthStatus, http.MethodGet},
		{types.PathAgentShutdown, http.MethodPost},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Host = "attack.example:4018"
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want forbidden", rec.Code)
			}
		})
	}
}
