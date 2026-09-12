package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestWalletAuthSIWE(t *testing.T) {
	owner := siweTestAuthority(t, "1")
	other := siweTestAuthority(t, "2")
	now := time.Now().UTC().Truncate(time.Second).Add(500 * time.Millisecond)
	for _, test := range []struct {
		name           string
		signer         LocalAuthority
		suffix         string
		delay          time.Duration
		shortSig       bool
		otherChallenge bool
		valid          bool
	}{
		{name: "owner", signer: owner, valid: true},
		{name: "wrong signer", signer: other},
		{name: "changed message", signer: owner, suffix: "!"},
		{name: "added whitespace", signer: owner, suffix: "\n"},
		{name: "expired", signer: owner, delay: 3 * time.Minute},
		{name: "signed expiration passed", signer: owner, delay: defaultWalletAuthChallengeTTL - 500*time.Millisecond + time.Nanosecond},
		{name: "expiration inclusive", signer: owner, delay: defaultWalletAuthChallengeTTL - 500*time.Millisecond, valid: true},
		{name: "short signature", signer: owner, shortSig: true},
		{name: "different challenge", signer: owner, otherChallenge: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, err := NewWalletAuthenticator(WalletAuthConfig{AllowedAddresses: []string{owner.Identity().Address}})
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := auth.IssueChallenge(types.WalletAuthChallengeRequest{Address: owner.Identity().Address}, "example.com", "https://example.com/login", now)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(challenge.SIWEMessage, "\nSign in to Portal\n\n") || !strings.HasSuffix(challenge.SIWEMessage, "Request ID: "+challenge.ChallengeID) {
				t.Fatalf("wallet message omitted challenge fields: %q", challenge.SIWEMessage)
			}
			message := challenge.SIWEMessage + test.suffix
			if test.otherChallenge {
				other, err := auth.IssueChallenge(types.WalletAuthChallengeRequest{Address: owner.Identity().Address}, "example.com", "https://example.com/login", now)
				if err != nil {
					t.Fatal(err)
				}
				message = other.SIWEMessage
			}
			signature, err := test.signer.SignEthereumPersonalMessage(message)
			if err != nil {
				t.Fatal(err)
			}
			if test.shortSig {
				signature = "0x12"
			}
			request := types.WalletAuthLoginRequest{ChallengeID: challenge.ChallengeID, SIWEMessage: message, SIWESignature: signature}
			token, address, err := auth.Login(request, now.Add(test.delay))
			if (err == nil) != test.valid {
				t.Fatalf("Login() = %v; want valid=%v", err, test.valid)
			}
			if !test.valid {
				if token != "" || address != "" {
					t.Fatal("failed login returned a session")
				}
				return
			}
			if token == "" || address != owner.Identity().Address {
				t.Fatalf("Login() token/address = %q/%q", token, address)
			}
			if sessionAddress, ok := auth.ValidateSession(token); !ok || sessionAddress != address {
				t.Fatalf("ValidateSession() = %q, %v", sessionAddress, ok)
			}
			if _, _, err := auth.Login(request, now.Add(test.delay)); err == nil {
				t.Fatal("consumed wallet challenge accepted a second time")
			}
		})
	}
}

func TestWalletAuthRejectsDisallowedChallenge(t *testing.T) {
	owner := siweTestAuthority(t, "1")
	other := siweTestAuthority(t, "2")
	auth, err := NewWalletAuthenticator(WalletAuthConfig{AllowedAddresses: []string{owner.Identity().Address}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.IssueChallenge(types.WalletAuthChallengeRequest{Address: other.Identity().Address}, "example.com", "https://example.com/login", time.Now()); err == nil {
		t.Fatal("disallowed wallet received a challenge")
	}
}
