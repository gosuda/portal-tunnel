package identity

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestRegisterChallengeSIWE(t *testing.T) {
	owner := siweTestAuthority(t, "1")
	other := siweTestAuthority(t, "2")
	now := time.Date(2026, 9, 12, 12, 0, 0, 500000000, time.UTC)
	challenge, err := NewRegisterChallenge(types.RegisterChallengeRequest{Identity: owner.Identity()}, "localhost:8443", "https://localhost:8443/register", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(challenge.SIWEMessage, "\nRegister a portal lease\n\n") || !strings.HasSuffix(challenge.SIWEMessage, "Request ID: "+challenge.ChallengeID) {
		t.Fatalf("registration message omitted challenge fields: %q", challenge.SIWEMessage)
	}
	for _, test := range []struct {
		name    string
		signer  LocalAuthority
		message string
		at      time.Time
		valid   bool
	}{
		{"owner", owner, challenge.SIWEMessage, now, true},
		{"wrong signer", other, challenge.SIWEMessage, now, false},
		{"changed message", owner, challenge.SIWEMessage + "!", now, false},
		{"added whitespace", owner, challenge.SIWEMessage + "\n", now, false},
		{"expiration inclusive", owner, challenge.SIWEMessage, challenge.ExpiresAt.Truncate(time.Second), true},
		{"signed expiration passed", owner, challenge.SIWEMessage, challenge.ExpiresAt.Truncate(time.Second).Add(time.Nanosecond), false},
		{"expired", owner, challenge.SIWEMessage, now.Add(2 * time.Minute), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			signature, err := test.signer.SignEthereumPersonalMessage(test.message)
			if err != nil {
				t.Fatal(err)
			}
			err = challenge.Verify(types.RegisterRequest{SIWEMessage: test.message, SIWESignature: signature}, test.at)
			if (err == nil) != test.valid {
				t.Fatalf("Verify() = %v; want valid=%v", err, test.valid)
			}
		})
	}
	if err := challenge.Verify(types.RegisterRequest{SIWEMessage: challenge.SIWEMessage, SIWESignature: "0x12"}, now); err == nil {
		t.Fatal("short signature accepted")
	}
}

func siweTestAuthority(t *testing.T, keyDigit string) LocalAuthority {
	t.Helper()
	resolved, err := resolve(types.Identity{Name: "siwe-test", PrivateKey: strings.Repeat("0", 63) + keyDigit})
	if err != nil {
		t.Fatal(err)
	}
	return NewLocalAuthority(resolved)
}

func TestValidateRegisterSIWEChallenge(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 500000000, time.UTC)
	relayURL, err := url.Parse("https://relay.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	const address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
	const challengeID = "rch_example"
	base := SIWEMessage{
		Domain: relayURL.Host, Address: address,
		URI:       "https://relay.example:8443" + types.PathSDKRegister,
		Statement: types.RegisterLeaseSIWEStatement,
		Nonce:     "abcdefgh12345678", RequestID: challengeID,
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}

	tests := []struct {
		name    string
		change  func(*SIWEMessage, *types.RegisterChallengeResponse)
		edit    func(string) string
		wantErr bool
	}{
		{name: "honest relay"},
		{name: "subsecond challenge", change: func(m *SIWEMessage, c *types.RegisterChallengeResponse) {
			m.ExpiresAt = m.IssuedAt.Add(100 * time.Millisecond)
			c.ExpiresAt = m.ExpiresAt
		}},
		{name: "other relying party", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Domain = "login.example"
			m.URI = "https://login.example/sign-in"
		}, wantErr: true},
		{name: "other domain", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Domain = "login.example"
		}, wantErr: true},
		{name: "other URI", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.URI = "https://relay.example:8443/login"
		}, wantErr: true},
		{name: "other identity", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Address = "0x0000000000000000000000000000000000000001"
		}, wantErr: true},
		{name: "other signing purpose", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.Statement = "Log in to another service"
		}, wantErr: true},
		{name: "other request ID", change: func(m *SIWEMessage, _ *types.RegisterChallengeResponse) {
			m.RequestID = "other_challenge"
		}, wantErr: true},
		{name: "challenge ID mismatch", change: func(_ *SIWEMessage, c *types.RegisterChallengeResponse) {
			c.ChallengeID = "other_challenge"
		}, wantErr: true},
		{name: "expiry mismatch", change: func(_ *SIWEMessage, c *types.RegisterChallengeResponse) {
			c.ExpiresAt = c.ExpiresAt.Add(time.Second)
		}, wantErr: true},
		{name: "excessive lifetime", change: func(m *SIWEMessage, c *types.RegisterChallengeResponse) {
			m.ExpiresAt = m.IssuedAt.Add(time.Hour)
			c.ExpiresAt = m.ExpiresAt
		}, wantErr: true},
		{name: "future issue time", change: func(m *SIWEMessage, c *types.RegisterChallengeResponse) {
			m.IssuedAt = now.Add(3 * time.Minute)
			m.ExpiresAt = m.IssuedAt.Add(time.Minute)
			c.ExpiresAt = m.ExpiresAt
		}, wantErr: true},
		{name: "expired", change: func(m *SIWEMessage, c *types.RegisterChallengeResponse) {
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
			formatted, err := FormatSIWEMessage(message)
			if err != nil {
				t.Fatalf("format test fixture: %v", err)
			}
			if tc.edit != nil {
				formatted = tc.edit(formatted)
			}
			challenge.SIWEMessage = formatted
			got := ValidateRegisterSIWEChallenge(challenge, relayURL, address, now)
			if (got != nil) != tc.wantErr {
				t.Fatalf("ValidateRegisterSIWEChallenge() error = %v, wantErr %t", got, tc.wantErr)
			}
		})
	}
}
