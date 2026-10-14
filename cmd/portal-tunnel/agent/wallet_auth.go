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

	mu       sync.Mutex
	sessions map[string]walletAuthSession
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
		siwe:     siwe,
		sessions: make(map[string]walletAuthSession),
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
// its existing session without extending expiration. Scanning at most 128
// sessions removes expired entries; eviction happens only when capacity is
// full. Fixed session TTLs make the earliest expiry the oldest.
func (a *walletAuthenticator) sessionForVerifiedWallet(address string, now time.Time) string {
	now = now.UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	var existingToken, oldestToken string
	var oldestExpiry time.Time
	for token, session := range a.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(a.sessions, token)
			continue
		}
		if session.Address == address {
			existingToken = token
		}
		if oldestToken == "" || session.ExpiresAt.Before(oldestExpiry) {
			oldestToken, oldestExpiry = token, session.ExpiresAt
		}
	}
	if existingToken != "" {
		return existingToken
	}
	if len(a.sessions) >= maxWalletAuthSessions {
		delete(a.sessions, oldestToken)
	}

	token := utils.RandomID("was_")
	a.sessions[token] = walletAuthSession{
		Address:   address,
		ExpiresAt: now.Add(defaultWalletAuthSessionTTL),
	}
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
		delete(a.sessions, token)
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
	delete(a.sessions, strings.TrimSpace(token))
}
