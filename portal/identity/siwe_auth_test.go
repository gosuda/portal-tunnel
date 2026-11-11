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

type signedWalletChallenge struct {
	auth      *SIWEAuthenticator
	wallet    LocalAuthority
	now       time.Time
	challenge SIWEChallenge
	signature string
}

func issueSignedWalletChallenge(t *testing.T) signedWalletChallenge {
	t.Helper()
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueTestChallenge(t, auth, wallet, now)
	signature, err := wallet.SignEthereumPersonalMessage(challenge.Message)
	if err != nil {
		t.Fatal(err)
	}
	return signedWalletChallenge{auth: auth, wallet: wallet, now: now, challenge: challenge, signature: signature}
}

func TestIssueIsStatelessUnderFlood(t *testing.T) {
	auth := newTestAuthenticator(t)
	wallet := testWallet(t)
	now := time.Now().UTC()
	challenge := issueChallengeFlood(t, auth, wallet, now)
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

func issueChallengeFlood(t *testing.T, auth *SIWEAuthenticator, wallet LocalAuthority, now time.Time) SIWEChallenge {
	t.Helper()
	const flood = 5000
	var challenge SIWEChallenge
	for i := range flood {
		var err error
		challenge, err = auth.Issue(wallet.Identity().Address, testDomain, "https://"+testDomain+"/", now)
		if err != nil {
			t.Fatalf("issue %d of %d: %v", i+1, flood, err)
		}
	}
	return challenge
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

	if _, err := auth.Verify(challenge.ID, challenge.Message, "", testDomain, time.Time{}, now.Add(siweChallengeTTL+time.Minute)); !errors.Is(err, ErrSIWEChallengeExpired) {
		t.Fatalf("err = %v; want ErrSIWEChallengeExpired", err)
	}
}

func TestVerifyRejectsChallengeFromBeforeNotBefore(t *testing.T) {
	signed := issueSignedWalletChallenge(t)
	if _, err := signed.auth.Verify(signed.challenge.ID, signed.challenge.Message, signed.signature, testDomain, signed.now.Add(time.Second), signed.now); !errors.Is(err, ErrSIWEChallengeExpired) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrSIWEChallengeExpired)
	}
	if _, err := signed.auth.Verify(signed.challenge.ID, signed.challenge.Message, signed.signature, testDomain, signed.now, signed.now); err != nil {
		t.Fatalf("Verify() from the first moment = %v", err)
	}
}

func TestVerifyAllowsReplayWithinTTL(t *testing.T) {
	signed := issueSignedWalletChallenge(t)
	for i := range 2 {
		address, err := signed.auth.Verify(signed.challenge.ID, signed.challenge.Message, signed.signature, testDomain, time.Time{}, signed.now)
		if err != nil {
			t.Fatalf("verify %d: %v", i+1, err)
		}
		if !strings.EqualFold(address, signed.wallet.Identity().Address) {
			t.Fatalf("address = %q; want %q", address, signed.wallet.Identity().Address)
		}
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	signed := issueSignedWalletChallenge(t)
	tampered := strings.Replace(signed.challenge.Message, "Sign in to Portal", "Sign in to Portsl", 1)
	if tampered == signed.challenge.Message {
		t.Fatal("message tamper did not change anything")
	}
	if _, err := signed.auth.Verify(signed.challenge.ID, tampered, signed.signature, testDomain, time.Time{}, signed.now); !errors.Is(err, ErrSIWEInvalidSignature) {
		t.Fatalf("err = %v; want ErrSIWEInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongDomain(t *testing.T) {
	signed := issueSignedWalletChallenge(t)
	if _, err := signed.auth.Verify(signed.challenge.ID, signed.challenge.Message, signed.signature, "other.example", time.Time{}, signed.now); !errors.Is(err, ErrSIWEInvalidSignature) {
		t.Fatalf("err = %v; want ErrSIWEInvalidSignature", err)
	}
}

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
