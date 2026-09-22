package siweauth

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
)

const testDomain = "app.example"

func newTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	auth, err := New(Config{Key: key, AllowAnyAddress: true, Statement: "Sign in to Portal", ChallengePrefix: "test_"})
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

func TestNewRejectsShortKey(t *testing.T) {
	if _, err := New(Config{Key: []byte("too-short"), AllowAnyAddress: true}); err == nil {
		t.Fatal("short challenge key accepted")
	}
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
	if len(auth.consumed) != 1 {
		t.Fatalf("consumed set = %d entries; want 1", len(auth.consumed))
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

func TestVerifyRejectsReplay(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}

	address, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if !strings.EqualFold(address, wallet.Identity().Address) {
		t.Fatalf("address = %q; want %q", address, wallet.Identity().Address)
	}
	if _, err := auth.Verify(challenge.ID, challenge.Message, signature, testDomain, now); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replay err = %v; want ErrChallengeNotFound", err)
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
