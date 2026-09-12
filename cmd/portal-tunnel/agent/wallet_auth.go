package agent

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultWalletAuthChallengeTTL = 2 * time.Minute
	defaultWalletAuthSessionTTL   = 24 * time.Hour
)

var (
	errWalletAuthUnauthorized      = errors.New("wallet is not allowed")
	errWalletAuthChallengeNotFound = errors.New("wallet auth challenge not found")
	errWalletAuthChallengeExpired  = errors.New("wallet auth challenge expired")
	errWalletAuthInvalidSignature  = errors.New("wallet auth signature is invalid")
)

type walletAuthConfig struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
}

type walletAuthenticator struct {
	allowed   map[string]struct{}
	allowAny  bool
	statement string

	mu         sync.Mutex
	challenges map[string]walletAuthChallenge
	sessions   map[string]walletAuthSession
}

type walletAuthChallenge struct {
	Address     string
	ExpiresAt   time.Time
	SIWEMessage string
}

type walletAuthSession struct {
	Address   string
	ExpiresAt time.Time
}

func newWalletAuthenticator(cfg walletAuthConfig) (*walletAuthenticator, error) {
	allowed := make(map[string]struct{}, len(cfg.AllowedAddresses))
	for _, raw := range cfg.AllowedAddresses {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		address, err := identity.NormalizeEVMAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("wallet address: %w", err)
		}
		allowed[strings.ToLower(address)] = struct{}{}
	}
	if !cfg.AllowAnyAddress && len(allowed) == 0 {
		return nil, errors.New("wallet auth requires at least one allowed address")
	}

	statement := strings.TrimSpace(cfg.Statement)
	statement = cmp.Or(statement, "Sign in to Portal")

	return &walletAuthenticator{
		allowed:    allowed,
		allowAny:   cfg.AllowAnyAddress,
		statement:  statement,
		challenges: make(map[string]walletAuthChallenge),
		sessions:   make(map[string]walletAuthSession),
	}, nil
}

func (a *walletAuthenticator) issueChallenge(req types.WalletAuthChallengeRequest, domain, uri string, now time.Time) (types.WalletAuthChallengeResponse, error) {
	if a == nil {
		return types.WalletAuthChallengeResponse{}, errWalletAuthUnauthorized
	}
	address, err := identity.NormalizeEVMAddress(req.Address)
	if err != nil {
		return types.WalletAuthChallengeResponse{}, err
	}
	if !a.addressAllowed(address) {
		return types.WalletAuthChallengeResponse{}, errWalletAuthUnauthorized
	}

	challengeID := utils.RandomID("wac_")
	expiresAt := now.UTC().Add(defaultWalletAuthChallengeTTL)
	message, err := identity.FormatSIWEMessage(types.SIWEMessage{
		Domain: domain, Address: address, URI: uri,
		Statement: a.statement, Nonce: rand.Text(), RequestID: challengeID,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return types.WalletAuthChallengeResponse{}, fmt.Errorf("build wallet auth message: %w", err)
	}

	challenge := walletAuthChallenge{
		Address:     address,
		ExpiresAt:   expiresAt,
		SIWEMessage: message,
	}

	a.mu.Lock()
	a.cleanupExpiredLocked(now)
	a.challenges[challengeID] = challenge
	a.mu.Unlock()

	return types.WalletAuthChallengeResponse{
		ChallengeID: challengeID,
		ExpiresAt:   expiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (a *walletAuthenticator) login(req types.WalletAuthLoginRequest, now time.Time) (string, string, error) {
	if a == nil {
		return "", "", errWalletAuthUnauthorized
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return "", "", errWalletAuthChallengeNotFound
	}

	a.mu.Lock()
	a.cleanupExpiredLocked(now)
	challenge, ok := a.challenges[challengeID]
	a.mu.Unlock()
	if !ok {
		return "", "", errWalletAuthChallengeNotFound
	}
	if now.After(challenge.ExpiresAt) {
		a.mu.Lock()
		delete(a.challenges, challengeID)
		a.mu.Unlock()
		return "", "", errWalletAuthChallengeExpired
	}
	if req.SIWEMessage != challenge.SIWEMessage {
		return "", "", errWalletAuthInvalidSignature
	}

	if err := identity.VerifySIWEMessage(challenge.SIWEMessage, req.SIWESignature, challenge.Address, challenge.ExpiresAt, now); err != nil {
		return "", "", errWalletAuthInvalidSignature
	}
	address := challenge.Address
	if !a.addressAllowed(address) {
		return "", "", errWalletAuthUnauthorized
	}

	token := utils.RandomID("was_")
	a.mu.Lock()
	delete(a.challenges, challengeID)
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

func (a *walletAuthenticator) addressAllowed(address string) bool {
	if a == nil {
		return false
	}
	if a.allowAny {
		return true
	}
	_, ok := a.allowed[strings.ToLower(strings.TrimSpace(address))]
	return ok
}

func (a *walletAuthenticator) cleanupExpiredLocked(now time.Time) {
	now = now.UTC()
	for id, challenge := range a.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(a.challenges, id)
		}
	}
	for token, session := range a.sessions {
		if now.After(session.ExpiresAt) {
			delete(a.sessions, token)
		}
	}
}
