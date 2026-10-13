package agent

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestWalletLoginReplayReusesSession(t *testing.T) {
	auth, err := newWalletAuthenticator(walletAuthConfig{AllowAnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := identity.ResolveSecp256k1Identity(strings.Repeat("0", 63) + "3")
	if err != nil {
		t.Fatal(err)
	}
	wallet := identity.NewLocalAuthority(resolved)
	domain := "127.0.0.1:4018"
	now := time.Now().UTC()
	challenge, err := auth.issueChallenge(
		types.WalletAuthChallengeRequest{Address: wallet.Identity().Address},
		domain, "http://"+domain+types.PathAgentAuthLogin, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wallet.SignEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		t.Fatal(err)
	}
	login := types.WalletAuthLoginRequest{
		ChallengeID: challenge.ChallengeID,
		SIWEMessage: challenge.SIWEMessage,
		SIWESignature: signature,
	}
	var first string
	for i := 0; i < 128; i++ {
		token, address, err := auth.login(login, domain, now)
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		if address != wallet.Identity().Address {
			t.Fatalf("address = %s, want %s", address, wallet.Identity().Address)
		}
		if i == 0 {
			first = token
		} else if token != first {
			t.Fatalf("login %d allocated a new token", i)
		}
	}
	if got := len(auth.sessions); got != 1 {
		t.Fatalf("sessions after replay = %d, want 1", got)
	}
	if got := len(auth.walletSessions); got != 1 {
		t.Fatalf("wallet indexes after replay = %d, want 1", got)
	}
}

func TestWalletSessionsStayGloballyBounded(t *testing.T) {
	auth, err := newWalletAuthenticator(walletAuthConfig{AllowAnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var first, last string
	for i := 0; i < 4*maxWalletAuthSessions; i++ {
		address := fmt.Sprintf("0x%040x", i+1)
		token := auth.sessionForVerifiedWallet(address, now)
		if i == 0 {
			first = token
		}
		last = token
		if len(auth.sessions) > maxWalletAuthSessions || len(auth.walletSessions) > maxWalletAuthSessions {
			t.Fatalf("session indexes exceeded %d entries", maxWalletAuthSessions)
		}
	}
	if _, ok := auth.validateSession(first); ok {
		t.Fatal("oldest session was not evicted")
	}
	if _, ok := auth.validateSession(last); !ok {
		t.Fatal("newest session should still be valid")
	}
	if len(auth.sessions) != maxWalletAuthSessions || len(auth.walletSessions) != maxWalletAuthSessions {
		t.Fatalf("session indexes = %d/%d, want %d each", len(auth.sessions), len(auth.walletSessions), maxWalletAuthSessions)
	}
}

func TestWalletSessionExpiryAndLogoutUpdateBothIndexes(t *testing.T) {
	auth, err := newWalletAuthenticator(walletAuthConfig{AllowAnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	address := "0x0000000000000000000000000000000000000001"
	now := time.Now().UTC()
	expired := auth.sessionForVerifiedWallet(address, now.Add(-defaultWalletAuthSessionTTL-time.Minute))
	current := auth.sessionForVerifiedWallet(address, now)
	if expired == current {
		t.Fatal("expired session was reused")
	}
	if _, ok := auth.validateSession(expired); ok {
		t.Fatal("expired session remained valid")
	}
	if got := len(auth.sessions); got != 1 {
		t.Fatalf("sessions = %d after expiry, want 1", got)
	}
	auth.deleteSession(current)
	if _, ok := auth.validateSession(current); ok {
		t.Fatal("deleted session remained valid")
	}
	if len(auth.sessions) != 0 || len(auth.walletSessions) != 0 {
		t.Fatalf("logout left session indexes populated: %d/%d", len(auth.sessions), len(auth.walletSessions))
	}
	next := auth.sessionForVerifiedWallet(address, now)
	if next == current {
		t.Fatal("session token reused after logout")
	}
}

func TestWalletSessionConcurrentReplay(t *testing.T) {
	auth, err := newWalletAuthenticator(walletAuthConfig{AllowAnyAddress: true})
	if err != nil {
		t.Fatal(err)
	}
	const count = 64
	tokens := make(chan string, count)
	var wg sync.WaitGroup
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens <- auth.sessionForVerifiedWallet("0x0000000000000000000000000000000000000001", now)
		}()
	}
	wg.Wait()
	close(tokens)
	var first string
	for token := range tokens {
		if first == "" {
			first = token
		} else if token != first {
			t.Fatal("concurrent replay allocated multiple sessions")
		}
	}
	if len(auth.sessions) != 1 || len(auth.walletSessions) != 1 {
		t.Fatalf("concurrent replay left %d/%d sessions, want 1 each", len(auth.sessions), len(auth.walletSessions))
	}
}
