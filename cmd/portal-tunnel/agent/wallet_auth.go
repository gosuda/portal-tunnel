package agent

import (
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultWalletAuthSessionTTL = 24 * time.Hour

type walletAuthConfig struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
}

type walletAuthenticator struct {
	siwe *siweAuthenticator

	mu       sync.Mutex
	sessions map[string]walletAuthSession
}

type walletAuthSession struct {
	Address   string
	ExpiresAt time.Time
}

func newWalletAuthenticator(cfg walletAuthConfig) (*walletAuthenticator, error) {
	siwe, err := newSIWEAuthenticator(siweAuthConfig{
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
		return types.WalletAuthChallengeResponse{}, errSIWEAuthUnauthorized
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
		return "", "", errSIWEAuthUnauthorized
	}
	address, err := a.siwe.Verify(req.ChallengeID, req.SIWEMessage, req.SIWESignature, domain, now)
	if err != nil {
		return "", "", err
	}

	token := utils.RandomID("was_")
	a.mu.Lock()
	a.sessions[token] = walletAuthSession{
		Address:   address,
		ExpiresAt: now.UTC().Add(defaultWalletAuthSessionTTL),
	}
	a.cleanupExpiredLocked(now)
	a.mu.Unlock()

	return token, address, nil
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
	if time.Now().UTC().After(session.ExpiresAt) {
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

func (a *walletAuthenticator) cleanupExpiredLocked(now time.Time) {
	now = now.UTC()
	for token, session := range a.sessions {
		if now.After(session.ExpiresAt) {
			delete(a.sessions, token)
		}
	}
}
