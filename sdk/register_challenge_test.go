package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestRegisterRejectsForeignSIWEChallenge(t *testing.T) {
	t.Parallel()

	leaseIdentity, err := identity.ResolveSecp256k1Identity("")
	if err != nil {
		t.Fatal(err)
	}
	leaseIdentity.Name = "defense"
	var registrationAttempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case types.PathSDKRegisterChallenge:
			challenge, err := identity.NewRegisterChallenge(
				types.RegisterChallengeRequest{Identity: leaseIdentity},
				"login.example", "https://login.example/sign-in", time.Now().UTC(), time.Minute,
			)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			utils.WriteAPIData(w, http.StatusCreated, types.RegisterChallengeResponse{
				ChallengeID: challenge.ChallengeID, ExpiresAt: challenge.ExpiresAt, SIWEMessage: challenge.SIWEMessage,
			})
		case types.PathSDKRegister:
			registrationAttempts.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	relayURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &apiClient{relayURL: relayURL, http: server.Client()}
	_, err = client.register(context.Background(), types.RegisterChallengeRequest{Identity: leaseIdentity}, "")
	if !errors.Is(err, identity.ErrInvalidRegisterSIWEChallenge) {
		t.Fatalf("registration error = %v, want invalid SIWE challenge", err)
	}
	if got := registrationAttempts.Load(); got != 0 {
		t.Fatalf("foreign SIWE challenge reached registration endpoint %d times", got)
	}
}
