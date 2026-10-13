package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestValidateRegisterSIWEChallenge(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 500000000, time.UTC)
	relayURL, err := url.Parse("https://relay.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	const address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
	const challengeID = "rch_example"
	base := identity.SIWEMessage{
		Domain: relayURL.Host, Address: address,
		URI:       "https://relay.example:8443" + types.PathSDKRegister,
		Statement: identity.RegisterLeaseSIWEStatement,
		Nonce:     "abcdefgh12345678", RequestID: challengeID,
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}

	tests := []struct {
		name    string
		change  func(*identity.SIWEMessage, *types.RegisterChallengeResponse)
		edit    func(string) string
		wantErr bool
	}{
		{name: "honest relay"},
		{name: "other relying party", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Domain = "login.example"
			m.URI = "https://login.example/sign-in"
		}, wantErr: true},
		{name: "other domain", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Domain = "login.example"
		}, wantErr: true},
		{name: "other URI", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.URI = "https://relay.example:8443/login"
		}, wantErr: true},
		{name: "other identity", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Address = "0x0000000000000000000000000000000000000001"
		}, wantErr: true},
		{name: "other signing purpose", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Statement = "Log in to another service"
		}, wantErr: true},
		{name: "other request ID", change: func(m *identity.SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.RequestID = "other_challenge"
		}, wantErr: true},
		{name: "challenge ID mismatch", change: func(_ *identity.SIWEMessage, c *types.RegisterChallengeResponse) {
			c.ChallengeID = "other_challenge"
		}, wantErr: true},
		{name: "expiry mismatch", change: func(_ *identity.SIWEMessage, c *types.RegisterChallengeResponse) {
			c.ExpiresAt = c.ExpiresAt.Add(time.Second)
		}, wantErr: true},
		{name: "excessive lifetime", change: func(m *identity.SIWEMessage, c *types.RegisterChallengeResponse) {
			m.ExpiresAt = m.IssuedAt.Add(time.Hour)
			c.ExpiresAt = m.ExpiresAt
		}, wantErr: true},
		{name: "future issue time", change: func(m *identity.SIWEMessage, c *types.RegisterChallengeResponse) {
			m.IssuedAt = now.Add(3 * time.Minute)
			m.ExpiresAt = m.IssuedAt.Add(time.Minute)
			c.ExpiresAt = m.ExpiresAt
		}, wantErr: true},
		{name: "expired", change: func(m *identity.SIWEMessage, c *types.RegisterChallengeResponse) {
			m.IssuedAt = now.Add(-3 * time.Minute)
			m.ExpiresAt = now.Add(-time.Minute)
			c.ExpiresAt = m.ExpiresAt
		}, wantErr: true},
		{name: "invalid nonce", edit: func(msg string) string {
			return strings.Replace(msg, "Nonce: abcdefgh12345678", "Nonce: short", 1)
		}, wantErr: true},
		{name: "different chain", edit: func(msg string) string {
			return strings.Replace(msg, "Chain ID: 1", "Chain ID: 137", 1)
		}, wantErr: true},
		{name: "different SIWE version", edit: func(msg string) string {
			return strings.Replace(msg, "Version: 1", "Version: 2", 1)
		}, wantErr: true},
		{name: "injected field", edit: func(msg string) string {
			return msg + "\nResources: https://login.example"
		}, wantErr: true},
		{name: "changed canonical whitespace", edit: func(msg string) string {
			return strings.Replace(msg, "\n\nURI: ", "\nURI: ", 1)
		}, wantErr: true},
		{name: "oversized message", edit: func(msg string) string {
			return msg + strings.Repeat("A", maxRegisterSIWEMessageBytes)
		}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			message := base
			challenge := types.RegisterChallengeResponse{ChallengeID: challengeID, ExpiresAt: base.ExpiresAt}
			if tc.change != nil {
				tc.change(&message, &challenge)
			}
			formatted, err := identity.FormatSIWEMessage(message)
			if err != nil {
				t.Fatalf("format test fixture: %v", err)
			}
			if tc.edit != nil {
				formatted = tc.edit(formatted)
			}
			challenge.SIWEMessage = formatted
			got := validateRegisterSIWEChallenge(challenge, relayURL, address, now)
			if (got != nil) != tc.wantErr {
				t.Fatalf("validateRegisterSIWEChallenge() error = %v, wantErr %t", got, tc.wantErr)
			}
		})
	}
}

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
	if !errors.Is(err, errInvalidRegisterSIWEChallenge) {
		t.Fatalf("registration error = %v, want invalid SIWE challenge", err)
	}
	if got := registrationAttempts.Load(); got != 0 {
		t.Fatalf("foreign SIWE challenge reached registration endpoint %d times", got)
	}
}
