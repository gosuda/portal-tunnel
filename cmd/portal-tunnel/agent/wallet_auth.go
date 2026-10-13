package agent

import (
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/siweauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultWalletAuthSessionTTL = 24 * time.Hour
	maxWalletAuthSessions       = 128
)

type walletAuthConfig struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
}

type walletAuthenticator struct {
	siwe *siweauth.Authenticator

	mu             sync.Mutex
	sessions       map[string]walletAuthSession
	walletSessions map[string]string
	recentTokens   [maxWalletAuthSessions]string
	nextTokenIndex int
}

type walletAuthSession struct {
	Address   string
	ExpiresAt time.Time
}

func newWalletAuthenticator(cfg walletAuthConfig) (*walletAuthenticator, error) {
	siwe, err := siweauth.New(siweauth.Config{
		AllowedAddresses: cfg.AllowedAddresses,
		AllowAnyAddress:  cfg.AllowAnyAddress,
		Statement:        cfg.Statement,
		ChallengePrefix:  "wac_",
	})
	if err != nil {
		return nil, err
	}
	return &walletAuthenticator{
		siwe:           siwe,
		sessions:       make(map[string]walletAuthSession),
		walletSessions: make(map[string]string),
	}, nil
}

func (a *walletAuthenticator) issueChallenge(req types.WalletAuthChallengeRequest, domain, uri string, now time.Time) (types.WalletAuthChallengeResponse, error) {
	if a == nil {
		return types.WalletAuthChallengeResponse{}, siweauth.ErrUnauthorized
	}
	challenge, err := a.siwe.Issue(req.Address, domain, uri, now)
	if err != nil {
		return types.WalletAuthChallengeResponse{}, err
	}
	return types.WalletAuthChallengeResponse{
		ChallengeID: challenge.ID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.Message,
	}, nil
}

func (a *walletAuthenticator) login(req types.WalletAuthLoginRequest, domain string, now time.Time) (string, string, error) {
	if a == nil {
		return "", "", siweauth.ErrUnauthorized
	}
	address, err := a.siwe.Verify(req.ChallengeID, req.SIWEMessage, req.SIWESignature, domain, now)
	if err != nil {
		return "", "", err
	}

	return a.sessionForVerifiedWallet(address, now), address, nil
}

// sessionForVerifiedWallet accepts only a SIWE-verified address. Replays reuse
// its existing session; new wallets evict the oldest issued session in O(1).
// Both indexes remain bounded without scanning them on every login.
func (a *walletAuthenticator) sessionForVerifiedWallet(address string, now time.Time) string {
	now = now.UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	if token := a.walletSessions[address]; token != "" {
		if session, ok := a.sessions[token]; ok && now.Before(session.ExpiresAt) {
			return token
		}
		a.removeSessionLocked(token)
	}

	a.removeSessionLocked(a.recentTokens[a.nextTokenIndex])
	token := utils.RandomID("was_")
	a.recentTokens[a.nextTokenIndex] = token
	a.nextTokenIndex = (a.nextTokenIndex + 1) % maxWalletAuthSessions
	a.sessions[token] = walletAuthSession{
		Address:   address,
		ExpiresAt: now.Add(defaultWalletAuthSessionTTL),
	}
	a.walletSessions[address] = token
	return token
}

func (a *walletAuthenticator) validateSession(token string) (string, bool) {
	if a == nil {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[token]
	if !ok {
		return "", false
	}
	if !time.Now().UTC().Before(session.ExpiresAt) {
		a.removeSessionLocked(token)
		return "", false
	}
	return session.Address, true
}

func (a *walletAuthenticator) deleteSession(token string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeSessionLocked(strings.TrimSpace(token))
}

// removeSessionLocked keeps both indexes consistent. a.mu must be held.
func (a *walletAuthenticator) removeSessionLocked(token string) {
	session, ok := a.sessions[token]
	if !ok {
		return
	}
	delete(a.sessions, token)
	delete(a.walletSessions, session.Address)
}
