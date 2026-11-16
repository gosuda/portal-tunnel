package portal

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRegisterChallengeProtocolSelection(t *testing.T) {
	registry := newTestRegistry(t, false, false)
	for _, version := range []string{"", types.SDKVersion, "unsupported"} {
		request := types.RegisterChallengeRequest{
			ProtocolVersion: version,
			Identity:        newTestLeaseIdentity(t, "compat"),
		}
		_, err := registry.issueRegisterChallenge(request, "example.com", "https://example.com"+types.PathSDKRegister, netip.Addr{})
		if version != "unsupported" {
			if err != nil {
				t.Fatalf("supported protocol %q: %v", version, err)
			}
			continue
		}
		var apiErr *apiError
		if !errors.As(err, &apiErr) || apiErr.status != http.StatusUpgradeRequired || apiErr.code != types.APIErrorCodeProtocolIncompatible {
			t.Fatalf("unsupported protocol must return an actionable incompatibility, got %v", err)
		}
	}
}
