package identity

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errWalletAuthRequiresLeastOneAllowed = errors.New("wallet auth requires at least one allowed address")
	errWalletAuthChallengeKeyTooShort    = errors.New("wallet auth challenge key must be at least 32 bytes")
)

const (
	siweChallengeTTL       = 2 * time.Minute
	siweChallengeKeyLength = 32
)

var (
	ErrSIWEUnauthorized      = errors.New("wallet is not allowed")
	ErrSIWEChallengeNotFound = errors.New("wallet auth challenge not found")
	ErrSIWEChallengeExpired  = errors.New("wallet auth challenge expired")
	ErrSIWEChallengeInvalid  = errors.New("wallet auth challenge is invalid")
	ErrSIWEInvalidSignature  = errors.New("wallet auth signature is invalid")
)

// SIWEAuthConfig configures the authenticator.
type SIWEAuthConfig struct {
	// ChallengeKey lets instances of one service verify each other's challenges.
	// Leave empty for instance-bound challenges. Use a domain-separated secret
	// of at least 32 bytes, shared only by the authenticators in that service.
	ChallengeKey     []byte
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
	ChallengePrefix  string
}

// SIWEAuthenticator issues and verifies stateless SIWE challenges. It is safe
// for concurrent use; construct with NewSIWEAuthenticator.
type SIWEAuthenticator struct {
	allowed         map[string]struct{}
	allowAny        bool
	statement       string
	challengePrefix string
	key             []byte
}

// SIWEChallenge is one issued sign-in request handed to the wallet.
type SIWEChallenge struct {
	ID        string
	Message   string
	ExpiresAt time.Time
}

type siweChallengePayload struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Domain    string    `json:"domain"`
	URI       string    `json:"uri"`
	Statement string    `json:"statement"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewSIWEAuthenticator validates the configuration and returns an authenticator.
// Without ChallengeKey it generates a fresh key, binding outstanding challenges
// to this instance. A supplied key is copied and remains private to the instance.
func NewSIWEAuthenticator(cfg SIWEAuthConfig) (*SIWEAuthenticator, error) {
	key := append([]byte(nil), cfg.ChallengeKey...)
	if len(key) == 0 {
		key = make([]byte, siweChallengeKeyLength)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate wallet auth challenge key: %w", err)
		}
	} else if len(key) < siweChallengeKeyLength {
		return nil, errWalletAuthChallengeKeyTooShort
	}
	addresses, err := NormalizeEVMAddresses(cfg.AllowedAddresses)
	if err != nil {
		return nil, err
	}
	if !cfg.AllowAnyAddress && len(addresses) == 0 {
		return nil, errWalletAuthRequiresLeastOneAllowed
	}
	allowed := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		allowed[strings.ToLower(address)] = struct{}{}
	}
	return &SIWEAuthenticator{
		allowed:         allowed,
		allowAny:        cfg.AllowAnyAddress,
		statement:       cmp.Or(strings.TrimSpace(cfg.Statement), "Sign in to Portal"),
		challengePrefix: strings.TrimSpace(cfg.ChallengePrefix),
		key:             key,
	}, nil
}

// ForBinding scopes challenges to an additional ownership boundary, such as
// an alias generation. It leaves the authenticator unchanged and does not
// retain state. An empty binding preserves the unbound challenge format.
func (a *SIWEAuthenticator) ForBinding(binding string) *SIWEAuthenticator {
	if a == nil || binding == "" {
		return a
	}
	bound := *a
	bound.key = a.sign([]byte("siwe-challenge-binding:" + binding))
	return &bound
}

// NormalizeEVMAddresses canonicalizes configured wallet addresses and
// de-duplicates them.
func NormalizeEVMAddresses(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		address, err := NormalizeEVMAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("wallet address: %w", err)
		}
		key := strings.ToLower(address)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, address)
	}
	return normalized, nil
}

// Issue returns a fresh challenge for address. It touches no shared state:
// a flood of unauthenticated challenge requests cannot exhaust issuance
// because there is no pending pool to fill.
func (a *SIWEAuthenticator) Issue(address, domain, uri string, now time.Time) (SIWEChallenge, error) {
	if a == nil {
		return SIWEChallenge{}, ErrSIWEUnauthorized
	}
	address, err := NormalizeEVMAddress(address)
	if err != nil {
		return SIWEChallenge{}, err
	}
	if !a.AddressAllowed(address) {
		return SIWEChallenge{}, ErrSIWEUnauthorized
	}
	domain = strings.TrimSpace(domain)
	now = now.UTC()
	expiresAt := now.Add(siweChallengeTTL)
	payload := siweChallengePayload{
		ID:        utils.RandomID(a.challengePrefix),
		Address:   address,
		Domain:    domain,
		URI:       uri,
		Statement: a.statement,
		Nonce:     rand.Text(),
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return SIWEChallenge{}, fmt.Errorf("encode wallet auth challenge: %w", err)
	}
	message, err := FormatSIWEMessage(SIWEMessage{
		Domain: payload.Domain, Address: address, URI: uri,
		Statement: a.statement, Nonce: payload.Nonce, RequestID: payload.ID,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return SIWEChallenge{}, fmt.Errorf("build wallet auth message: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.sign(raw))
	return SIWEChallenge{ID: token, Message: message, ExpiresAt: expiresAt}, nil
}

// Verify validates a signed challenge token together with the wallet's
// signature over its message and returns the address. A verified
// challenge is a short-lived proof: re-submitting the same token and
// signature within its TTL re-authenticates the same wallet, so there is
// no replay tracking. An unknown or blank token answers
// ErrSIWEChallengeNotFound.
func (a *SIWEAuthenticator) Verify(challengeToken, message, signature, domain string, notBefore, now time.Time) (string, error) {
	if a == nil {
		return "", ErrSIWEUnauthorized
	}
	challengeToken = strings.TrimSpace(challengeToken)
	if challengeToken == "" {
		return "", ErrSIWEChallengeNotFound
	}
	now = now.UTC()

	payload, err := a.decodeChallengeToken(challengeToken)
	if err != nil {
		return "", err
	}
	if now.After(payload.ExpiresAt) || payload.IssuedAt.Before(notBefore) {
		return "", ErrSIWEChallengeExpired
	}
	expected, err := FormatSIWEMessage(SIWEMessage{
		Domain: payload.Domain, Address: payload.Address, URI: payload.URI,
		Statement: payload.Statement, Nonce: payload.Nonce, RequestID: payload.ID,
		IssuedAt: payload.IssuedAt, ExpiresAt: payload.ExpiresAt,
	})
	if err != nil || message != expected {
		return "", ErrSIWEInvalidSignature
	}
	if !strings.EqualFold(payload.Domain, strings.TrimSpace(domain)) {
		return "", ErrSIWEInvalidSignature
	}
	if err := VerifySIWEMessage(message, signature, payload.Address, payload.ExpiresAt, now); err != nil {
		return "", ErrSIWEInvalidSignature
	}
	if !a.AddressAllowed(payload.Address) {
		return "", ErrSIWEUnauthorized
	}
	return payload.Address, nil
}

func (a *SIWEAuthenticator) decodeChallengeToken(token string) (siweChallengePayload, error) {
	encodedPayload, encodedMAC, ok := strings.Cut(token, ".")
	if !ok {
		return siweChallengePayload{}, ErrSIWEChallengeInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return siweChallengePayload{}, ErrSIWEChallengeInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || !hmac.Equal(mac, a.sign(raw)) {
		return siweChallengePayload{}, ErrSIWEChallengeInvalid
	}
	var payload siweChallengePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return siweChallengePayload{}, ErrSIWEChallengeInvalid
	}
	if payload.ID == "" || payload.Address == "" || payload.Domain == "" || payload.Nonce == "" {
		return siweChallengePayload{}, ErrSIWEChallengeInvalid
	}
	return payload, nil
}

// AddressAllowed reports whether address may authenticate.
func (a *SIWEAuthenticator) AddressAllowed(address string) bool {
	if a == nil {
		return false
	}
	if a.allowAny {
		return true
	}
	_, ok := a.allowed[strings.ToLower(strings.TrimSpace(address))]
	return ok
}

func (a *SIWEAuthenticator) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
