package siweauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

const testDomain = "app.example"

func newTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	auth, err := New(Config{AllowAnyAddress: true, Statement: "Sign in to Portal", ChallengePrefix: "test_"})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func testWallet(t *testing.T) identity.LocalAuthority {
	t.Helper()
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + "3")
	if err != nil {
		t.Fatal(err)
	}
	return identity.NewLocalAuthority(resolved)
}

func issueTestChallenge(t *testing.T, auth *Authenticator, wallet identity.LocalAuthority, now time.Time) Challenge {
	t.Helper()
	challenge, err := auth.Issue(wallet.Identity().Address, testDomain, "https://"+testDomain+"/", now)
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

// TestIssueIsStatelessUnderFlood is the issue #530 regression: issuance
// must never fail for volume alone, even far past the old 4096 pending
// pool, and a challenge issued after the flood still verifies.
func TestIssueIsStatelessUnderFlood(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()

	const flood = 5000
	var challenge Challenge
	var err error
	for i := 0; i < flood; i++ {
		challenge, err = auth.Issue(wallet.Identity().Address, testDomain, "https://"+testDomain+"/", now)
		if err != nil {
			t.Fatalf("issue %d of %d: %v", i+1, flood, err)
		}
	}
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	address, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now)
	if err != nil {
		t.Fatalf("verify after flood: %v", err)
	}
	if !strings.EqualFold(address, wallet.Identity().Address) {
		t.Fatalf("address = %q; want %q", address, wallet.Identity().Address)
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)

	payload, mac, _ := strings.Cut(challenge.ID, ".")
	flip := func(encoded string) string {
		if strings.HasPrefix(encoded, "A") {
			return "B" + encoded[1:]
		}
		return "A" + encoded[1:]
	}
	tampered := map[string]string{
		"payload": flip(payload) + "." + mac,
		"mac":     payload + "." + flip(mac),
		"format":  payload,
	}
	for name, token := range tampered {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.Verify(token, challenge.Message, "", testDomain, now); !errors.Is(err, ErrChallengeInvalid) {
				t.Fatalf("err = %v; want ErrChallengeInvalid", err)
			}
		})
	}
}

func TestVerifyRejectsExpiredChallenge(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)

	// Expiry is checked before the signature, so an unsigned placeholder
	// keeps the assertion on the expiry path.
	if _, err := auth.Verify(challenge.ID, challenge.Message, "", testDomain, now.Add(challengeTTL+time.Minute)); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("err = %v; want ErrChallengeExpired", err)
	}
}

// TestVerifyAllowsReplayWithinTTL pins the accepted session semantic: a
// verified challenge is a short-lived proof, so re-submitting the same
// token and signature re-authenticates the same wallet. Replay tracking
// is deliberately omitted: it cannot create a new identity, and its
// global consumed set would reintroduce the capacity failure mode issue
// #530 removes.
func TestVerifyAllowsReplayWithinTTL(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		address, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now)
		if err != nil {
			t.Fatalf("verify %d: %v", i+1, err)
		}
		if !strings.EqualFold(address, wallet.Identity().Address) {
			t.Fatalf("address = %q; want %q", address, wallet.Identity().Address)
		}
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	// A valid signature over the issued message plus any edit to the
	// submitted message must fail: the wallet signs exactly what is issued.
	tampered := strings.Replace(challenge.Message, "Sign in to Portal", "Sign in to Portsl", 1)
	if tampered == challenge.Message {
		t.Fatal("message tamper did not change anything")
	}
	if _, err := auth.Verify(challenge.ID, tampered, signature, testDomain, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v; want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongDomain(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Verify(challenge.ID, challenge.Message, signature, "other.example", now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v; want ErrInvalidSignature", err)
	}
}

// TestNewKeyIsInstanceLocal pins the instance rule: each authenticator
// signs with its own freshly generated key, so a recreated authenticator
// rejects challenges issued by the previous instance. Challenges are
// instance-bound, not process-bound: a managed tunnel can recreate its
// authenticator within the same process.
func TestNewKeyIsInstanceLocal(t *testing.T) {
	wallet := testWallet(t)
	now := time.Now().UTC()
	first := newTestAuthenticator(t)
	challenge := issueTestChallenge(t, first, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Verify(challenge.ID, challenge.Message, signature, testDomain, now); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	recreated := newTestAuthenticator(t)
	if _, err := recreated.Verify(challenge.ID, challenge.Message, signature, testDomain, now); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("recreated-instance err = %v; want ErrChallengeInvalid", err)
	}
}
