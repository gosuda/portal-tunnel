package identity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testDomain = "app.example"

func newTestAuthenticator(t *testing.T) *SIWEAuthenticator {
	t.Helper()
	auth, err := NewSIWEAuthenticator(SIWEAuthConfig{AllowAnyAddress: true, Statement: "Sign in to Portal", ChallengePrefix: "test_"})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func testWallet(t *testing.T) LocalAuthority {
	t.Helper()
	resolved, err := ResolveSecp256k1Identity(strings.Repeat("0", 63) + "3")
	if err != nil {
		t.Fatal(err)
	}
	return NewLocalAuthority(resolved)
}

func issueTestChallenge(t *testing.T, auth *SIWEAuthenticator, wallet LocalAuthority, now time.Time) SIWEChallenge {
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
	var challenge SIWEChallenge
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
	address, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, time.Time{}, now)
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
			if _, err := auth.Verify(token, challenge.Message, "", testDomain, time.Time{}, now); !errors.Is(err, ErrSIWEChallengeInvalid) {
				t.Fatalf("err = %v; want ErrSIWEChallengeInvalid", err)
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
	if _, err := auth.Verify(challenge.ID, challenge.Message, "", testDomain, time.Time{}, now.Add(siweChallengeTTL+time.Minute)); !errors.Is(err, ErrSIWEChallengeExpired) {
		t.Fatalf("err = %v; want ErrSIWEChallengeExpired", err)
	}
}

// TestVerifyAllowsReplayWithinTTL pins the accepted session semantic: a
// verified challenge is a short-lived proof, so re-submitting the same
// token and signature re-authenticates the same wallet. Replay tracking
// is deliberately omitted: it cannot create a new identity, and its
// global consumed set would reintroduce the capacity failure mode issue
// #530 removes.
func TestVerifyRejectsChallengeFromBeforeNotBefore(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now.Add(time.Second), now); !errors.Is(err, ErrSIWEChallengeExpired) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrSIWEChallengeExpired)
	}
	if _, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now, now); err != nil {
		t.Fatalf("Verify() from the first moment = %v", err)
	}
}

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
		address, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, time.Time{}, now)
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
	if _, err := auth.Verify(challenge.ID, tampered, signature, testDomain, time.Time{}, now); !errors.Is(err, ErrSIWEInvalidSignature) {
		t.Fatalf("err = %v; want ErrSIWEInvalidSignature", err)
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
	if _, err := auth.Verify(challenge.ID, challenge.Message, signature, "other.example", time.Time{}, now); !errors.Is(err, ErrSIWEInvalidSignature) {
		t.Fatalf("err = %v; want ErrSIWEInvalidSignature", err)
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
	if _, err := first.Verify(challenge.ID, challenge.Message, signature, testDomain, time.Time{}, now); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	recreated := newTestAuthenticator(t)
	if _, err := recreated.Verify(challenge.ID, challenge.Message, signature, testDomain, time.Time{}, now); !errors.Is(err, ErrSIWEChallengeInvalid) {
		t.Fatalf("recreated-instance err = %v; want ErrSIWEChallengeInvalid", err)
	}
}
