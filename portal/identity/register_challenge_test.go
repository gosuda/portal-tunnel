package identity

import (
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
	authority, err := NewLocalAuthority(types.Identity{Name: "siwe-test", PrivateKey: strings.Repeat("0", 63) + keyDigit})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
