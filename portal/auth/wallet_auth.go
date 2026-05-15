package auth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spruceid/siwe-go"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultWalletAuthChallengeTTL = 2 * time.Minute
	defaultWalletAuthSessionTTL   = 24 * time.Hour
)

var (
	ErrWalletAuthUnauthorized      = errors.New("wallet is not allowed")
	ErrWalletAuthChallengeNotFound = errors.New("wallet auth challenge not found")
	ErrWalletAuthChallengeExpired  = errors.New("wallet auth challenge expired")
	ErrWalletAuthInvalidSignature  = errors.New("wallet auth signature is invalid")
)

type WalletAuthConfig struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
}

type WalletAuthenticator struct {
	allowed   map[string]struct{}
	allowAny  bool
	statement string

	mu         sync.Mutex
	challenges map[string]walletAuthChallenge
	sessions   map[string]walletAuthSession
}

type walletAuthChallenge struct {
	Address     string
	Domain      string
	ExpiresAt   time.Time
	Nonce       string
	SIWEMessage string
}

type walletAuthSession struct {
	Address   string
	ExpiresAt time.Time
}

func NewWalletAuthenticator(cfg WalletAuthConfig) (*WalletAuthenticator, error) {
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
	if statement == "" {
		statement = "Sign in to Portal"
	}

	return &WalletAuthenticator{
		allowed:    allowed,
		allowAny:   cfg.AllowAnyAddress,
		statement:  statement,
		challenges: make(map[string]walletAuthChallenge),
		sessions:   make(map[string]walletAuthSession),
	}, nil
}

func (a *WalletAuthenticator) IssueChallenge(req types.WalletAuthChallengeRequest, domain, uri string, now time.Time) (types.WalletAuthChallengeResponse, error) {
	if a == nil {
		return types.WalletAuthChallengeResponse{}, ErrWalletAuthUnauthorized
	}
	address, err := identity.NormalizeEVMAddress(req.Address)
	if err != nil {
		return types.WalletAuthChallengeResponse{}, err
	}
	if !a.addressAllowed(address) {
		return types.WalletAuthChallengeResponse{}, ErrWalletAuthUnauthorized
	}

	challengeID := utils.RandomID("wac_")
	nonce := siwe.GenerateNonce()
	expiresAt := now.UTC().Add(defaultWalletAuthChallengeTTL)
	message, err := siwe.InitMessage(domain, address, uri, nonce, map[string]interface{}{
		"statement":      a.statement,
		"chainId":        1,
		"issuedAt":       now.UTC().Format(time.RFC3339),
		"expirationTime": expiresAt.UTC().Format(time.RFC3339),
		"requestId":      challengeID,
	})
	if err != nil {
		return types.WalletAuthChallengeResponse{}, fmt.Errorf("build wallet auth message: %w", err)
	}

	challenge := walletAuthChallenge{
		Address:     address,
		Domain:      strings.TrimSpace(domain),
		ExpiresAt:   expiresAt,
		Nonce:       nonce,
		SIWEMessage: message.String(),
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

func (a *WalletAuthenticator) Login(req types.WalletAuthLoginRequest, now time.Time) (string, string, error) {
	if a == nil {
		return "", "", ErrWalletAuthUnauthorized
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return "", "", ErrWalletAuthChallengeNotFound
	}

	a.mu.Lock()
	a.cleanupExpiredLocked(now)
	challenge, ok := a.challenges[challengeID]
	a.mu.Unlock()
	if !ok {
		return "", "", ErrWalletAuthChallengeNotFound
	}
	if now.After(challenge.ExpiresAt) {
		a.mu.Lock()
		delete(a.challenges, challengeID)
		a.mu.Unlock()
		return "", "", ErrWalletAuthChallengeExpired
	}
	if strings.TrimSpace(req.SIWEMessage) != challenge.SIWEMessage {
		return "", "", ErrWalletAuthInvalidSignature
	}

	message, err := siwe.ParseMessage(strings.TrimSpace(req.SIWEMessage))
	if err != nil {
		return "", "", ErrWalletAuthInvalidSignature
	}
	domain := challenge.Domain
	nonce := challenge.Nonce
	verifiedAt := now.UTC()
	if _, err := message.Verify(strings.TrimSpace(req.SIWESignature), &domain, &nonce, &verifiedAt); err != nil {
		return "", "", ErrWalletAuthInvalidSignature
	}
	address, err := identity.NormalizeEVMAddress(message.GetAddress().Hex())
	if err != nil {
		return "", "", ErrWalletAuthInvalidSignature
	}
	if !strings.EqualFold(address, challenge.Address) || !a.addressAllowed(address) {
		return "", "", ErrWalletAuthUnauthorized
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

func (a *WalletAuthenticator) ValidateSession(token string) (string, bool) {
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

func (a *WalletAuthenticator) DeleteSession(token string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, strings.TrimSpace(token))
}

func (a *WalletAuthenticator) addressAllowed(address string) bool {
	if a == nil {
		return false
	}
	if a.allowAny {
		return true
	}
	_, ok := a.allowed[strings.ToLower(strings.TrimSpace(address))]
	return ok
}

func (a *WalletAuthenticator) cleanupExpiredLocked(now time.Time) {
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
