package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestAPIClientUsesExplicitProtocolSupport(t *testing.T) {
	for _, test := range []struct {
		name       string
		domain     types.DomainResponse
		compatible bool
	}{
		{"older relay", types.DomainResponse{ProtocolVersion: types.SDKVersion}, true},
		{"newer compatible relay", types.DomainResponse{ProtocolVersion: "future", SupportedProtocolVersions: []string{types.SDKVersion, "future"}}, true},
		{"explicitly unsupported", types.DomainResponse{ProtocolVersion: types.SDKVersion, SupportedProtocolVersions: []string{"other"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != types.PathSDKDomain {
					http.NotFound(w, r)
					return
				}
				utils.WriteAPIData(w, http.StatusOK, test.domain)
			}))
			defer server.Close()
			relayURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client := &apiClient{relayURL: relayURL}
			defer client.resetTransport()
			err = client.initHTTPTransport(t.Context())
			if test.compatible && err != nil {
				t.Fatalf("compatible relay rejected: %v", err)
			}
			if !test.compatible && !errors.Is(err, errRelayIncompatible) {
				t.Fatalf("unsupported protocol error = %v", err)
			}
		})
	}
}

func TestAPIClientDoesNotDowngradeRequestedFeatures(t *testing.T) {
	client := &apiClient{http: http.DefaultClient}
	for _, request := range []types.RegisterChallengeRequest{
		{Namespace: types.LocalTLSNamespaceV1},
		{Replica: true},
	} {
		if _, err := client.register(context.Background(), request, ""); !errors.Is(err, errRelayIncompatible) {
			t.Fatalf("missing capability must fail before registration, got %v", err)
		}
	}
}
