package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	defaultSuiAuthRPCURL          = "https://sui-rpc.publicnode.com"

	walletAuthMethodSuiWallet = "sui_wallet"
	walletAuthMethodZkLogin   = "zklogin"
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
	SuiRPCURL        string
}

type WalletAuthenticator struct {
	allowed   map[string]struct{}
	allowAny  bool
	statement string
	suiRPCURL string

	mu         sync.Mutex
	challenges map[string]walletAuthChallenge
	sessions   map[string]walletAuthSession
}

type walletAuthChallenge struct {
	Address    string
	AuthMethod string
	ExpiresAt  time.Time
	Message    string
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
		address, err := identity.NormalizeSuiAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("wallet address: %w", err)
		}
		allowed[strings.ToLower(address)] = struct{}{}
	}
	if !cfg.AllowAnyAddress && len(allowed) == 0 {
		return nil, errors.New("wallet auth requires at least one allowed Sui address")
	}

	statement := strings.TrimSpace(cfg.Statement)
	if statement == "" {
		statement = "Sign in to Portal"
	}
	suiRPCURL := strings.TrimSpace(cfg.SuiRPCURL)
	if suiRPCURL == "" {
		suiRPCURL = defaultSuiAuthRPCURL
	}

	return &WalletAuthenticator{
		allowed:    allowed,
		allowAny:   cfg.AllowAnyAddress,
		statement:  statement,
		suiRPCURL:  suiRPCURL,
		challenges: make(map[string]walletAuthChallenge),
		sessions:   make(map[string]walletAuthSession),
	}, nil
}

func (a *WalletAuthenticator) IssueChallenge(req types.WalletAuthChallengeRequest, domain, uri string, now time.Time) (types.WalletAuthChallengeResponse, error) {
	if a == nil {
		return types.WalletAuthChallengeResponse{}, ErrWalletAuthUnauthorized
	}
	address, err := identity.NormalizeSuiAddress(req.Address)
	if err != nil {
		return types.WalletAuthChallengeResponse{}, err
	}
	if !a.addressAllowed(address) {
		return types.WalletAuthChallengeResponse{}, ErrWalletAuthUnauthorized
	}

	authMethod := normalizeWalletAuthMethod(req.AuthMethod)
	challengeID := utils.RandomID("wac_")
	nonce := utils.RandomID("nonce_")
	expiresAt := now.UTC().Add(defaultWalletAuthChallengeTTL)
	message := buildSuiAuthMessage(a.statement, strings.TrimSpace(domain), strings.TrimSpace(uri), address, nonce, challengeID, now.UTC(), expiresAt)
	challenge := walletAuthChallenge{
		Address:    address,
		AuthMethod: authMethod,
		ExpiresAt:  expiresAt,
		Message:    message,
	}

	a.mu.Lock()
	a.cleanupExpiredLocked(now)
	a.challenges[challengeID] = challenge
	a.mu.Unlock()

	return types.WalletAuthChallengeResponse{
		ChallengeID: challengeID,
		ExpiresAt:   expiresAt,
		Message:     challenge.Message,
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
	if strings.TrimSpace(req.Message) != challenge.Message {
		return "", "", ErrWalletAuthInvalidSignature
	}
	if method := normalizeWalletAuthMethod(req.AuthMethod); method != "" && method != challenge.AuthMethod {
		return "", "", ErrWalletAuthInvalidSignature
	}

	address, err := identity.VerifySuiPersonalMessageSignature([]byte(challenge.Message), req.Signature, a.verifyZkLoginPersonalMessage)
	if err != nil {
		return "", "", ErrWalletAuthInvalidSignature
	}
	if !strings.EqualFold(address, challenge.Address) || !a.addressAllowed(address) {
		return "", "", ErrWalletAuthUnauthorized
	}
	if reqAddress := strings.TrimSpace(req.Address); reqAddress != "" {
		normalized, err := identity.NormalizeSuiAddress(reqAddress)
		if err != nil || !strings.EqualFold(normalized, challenge.Address) {
			return "", "", ErrWalletAuthUnauthorized
		}
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

func (a *WalletAuthenticator) verifyZkLoginPersonalMessage(author string, message []byte, signature string) (bool, error) {
	rpcURL := strings.TrimSpace(a.suiRPCURL)
	if rpcURL == "" {
		rpcURL = defaultSuiAuthRPCURL
	}
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "sui_verifyZkLoginSignature",
		"params": []any{
			base64.StdEncoding.EncodeToString(message),
			strings.TrimSpace(signature),
			"PersonalMessage",
			strings.TrimSpace(author),
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var out struct {
		Result struct {
			Success bool     `json:"success"`
			Errors  []string `json:"errors"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	if out.Error != nil {
		return false, errors.New(out.Error.Message)
	}
	return out.Result.Success && len(out.Result.Errors) == 0, nil
}

func normalizeWalletAuthMethod(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", walletAuthMethodSuiWallet:
		return walletAuthMethodSuiWallet
	case walletAuthMethodZkLogin:
		return walletAuthMethodZkLogin
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func buildSuiAuthMessage(statement, domain, uri, address, nonce, requestID string, issuedAt, expiresAt time.Time) string {
	lines := []string{
		strings.TrimSpace(statement),
		"",
		"Domain: " + strings.TrimSpace(domain),
		"URI: " + strings.TrimSpace(uri),
		"Sui Address: " + strings.TrimSpace(address),
		"Nonce: " + strings.TrimSpace(nonce),
		"Issued At: " + issuedAt.UTC().Format(time.RFC3339),
		"Expiration Time: " + expiresAt.UTC().Format(time.RFC3339),
		"Request ID: " + strings.TrimSpace(requestID),
	}
	return strings.Join(lines, "\n")
}
