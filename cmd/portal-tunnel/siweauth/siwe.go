// Package siweauth issues and verifies SIWE (Sign-In with Ethereum)
// challenges for tunnel-local wallet authentication.
//
// Challenges are stateless and tamper-evident: Issue encodes the challenge
// payload into an HMAC-signed token instead of storing pending state, so
// issuance consumes no server state and an unauthenticated flood of
// challenge requests cannot exhaust login capacity (issue #530). The token
// travels to the wallet as the opaque challenge ID and doubles as the SIWE
// request ID. The only stored state is a bounded consumed-replay set that
// keeps a verified challenge from being used twice. Source IP addresses and
// relay connection identities are deliberately not used to rate-limit
// issuance: neither is a trustworthy browser identity through relay
// transport, so limiting on them would only block the wrong clients.
package siweauth

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	// challengeTTL bounds how long a wallet has to sign its challenge.
	challengeTTL = 2 * time.Minute
	// consumedMax bounds the replay set. It is not an issuance limit:
	// hitting it only evicts the entry closest to expiry.
	consumedMax = 4096
	// minKeyLength is the smallest acceptable HMAC key.
	minKeyLength = 32
)

var (
	ErrUnauthorized      = errors.New("wallet is not allowed")
	ErrChallengeNotFound = errors.New("wallet auth challenge not found")
	ErrChallengeExpired  = errors.New("wallet auth challenge expired")
	ErrChallengeInvalid  = errors.New("wallet auth challenge is invalid")
	ErrInvalidSignature  = errors.New("wallet auth signature is invalid")
)

// Config configures the authenticator. Key must be at least minKeyLength
// bytes of cryptographically random material; it authenticates every
// issued challenge token.
type Config struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
	ChallengePrefix  string
	Key              []byte
}

// Authenticator issues and verifies stateless SIWE challenges. It is safe
// for concurrent use; construct with New.
type Authenticator struct {
	allowed         map[string]struct{}
	allowAny        bool
	statement       string
	challengePrefix string
	key             []byte

	mu       sync.Mutex
	consumed map[string]time.Time
}

// Challenge is one issued sign-in request handed to the wallet.
type Challenge struct {
	ID        string
	Message   string
	ExpiresAt time.Time
}

// challengePayload is the HMAC-protected body of a challenge token. Its
// canonical JSON encoding (struct field order, deterministic) is what the
// MAC covers.
type challengePayload struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Domain    string    `json:"domain"`
	URI       string    `json:"uri"`
	Statement string    `json:"statement"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// New validates the configuration and returns an authenticator.
func New(cfg Config) (*Authenticator, error) {
	if len(cfg.Key) < minKeyLength {
		return nil, fmt.Errorf("wallet auth challenge key must be at least %d bytes", minKeyLength)
	}
	addresses, err := NormalizeAddresses(cfg.AllowedAddresses)
	if err != nil {
		return nil, err
	}
	if !cfg.AllowAnyAddress && len(addresses) == 0 {
		return nil, errors.New("wallet auth requires at least one allowed address")
	}
	allowed := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		allowed[strings.ToLower(address)] = struct{}{}
	}
	return &Authenticator{
		allowed:         allowed,
		allowAny:        cfg.AllowAnyAddress,
		statement:       cmp.Or(strings.TrimSpace(cfg.Statement), "Sign in to Portal"),
		challengePrefix: strings.TrimSpace(cfg.ChallengePrefix),
		key:             bytes.Clone(cfg.Key),
		consumed:        make(map[string]time.Time),
	}, nil
}

// NormalizeAddresses canonicalizes configured wallet addresses and
// de-duplicates them.
func NormalizeAddresses(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		address, err := identity.NormalizeEVMAddress(raw)
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
// because there is no pending pool to fill (issue #530).
func (a *Authenticator) Issue(address, domain, uri string, now time.Time) (Challenge, error) {
	if a == nil {
		return Challenge{}, ErrUnauthorized
	}
	address, err := identity.NormalizeEVMAddress(address)
	if err != nil {
		return Challenge{}, err
	}
	if !a.AddressAllowed(address) {
		return Challenge{}, ErrUnauthorized
	}
	domain = strings.TrimSpace(domain)
	now = now.UTC()
	expiresAt := now.Add(challengeTTL)
	payload := challengePayload{
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
		return Challenge{}, fmt.Errorf("encode wallet auth challenge: %w", err)
	}
	message, err := identity.FormatSIWEMessage(identity.SIWEMessage{
		Domain: payload.Domain, Address: address, URI: uri,
		Statement: a.statement, Nonce: payload.Nonce, RequestID: payload.ID,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return Challenge{}, fmt.Errorf("build wallet auth message: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(a.sign(raw))
	return Challenge{ID: token, Message: message, ExpiresAt: expiresAt}, nil
}

// Verify validates a signed challenge token together with the wallet's
// signature over its message. On success the address is returned and the
// token is recorded as consumed; a consumed or unknown token answers
// ErrChallengeNotFound.
func (a *Authenticator) Verify(challengeToken, message, signature, domain string, now time.Time) (string, error) {
	if a == nil {
		return "", ErrUnauthorized
	}
	challengeToken = strings.TrimSpace(challengeToken)
	if challengeToken == "" {
		return "", ErrChallengeNotFound
	}
	now = now.UTC()

	payload, err := a.decodeChallengeToken(challengeToken)
	if err != nil {
		return "", err
	}
	if now.After(payload.ExpiresAt) {
		return "", ErrChallengeExpired
	}
	// Rebuild the message from the HMAC-protected payload and require
	// byte-for-byte equality: the wallet signs exactly what was issued,
	// so an edited message invalidates the challenge without creating a
	// second validation path through the submitted text.
	expected, err := identity.FormatSIWEMessage(identity.SIWEMessage{
		Domain: payload.Domain, Address: payload.Address, URI: payload.URI,
		Statement: payload.Statement, Nonce: payload.Nonce, RequestID: payload.ID,
		IssuedAt: payload.IssuedAt, ExpiresAt: payload.ExpiresAt,
	})
	if err != nil || message != expected {
		return "", ErrInvalidSignature
	}
	if !strings.EqualFold(payload.Domain, strings.TrimSpace(domain)) {
		return "", ErrInvalidSignature
	}
	if err := identity.VerifySIWEMessage(message, signature, payload.Address, payload.ExpiresAt, now); err != nil {
		return "", ErrInvalidSignature
	}
	if !a.AddressAllowed(payload.Address) {
		return "", ErrUnauthorized
	}
	if err := a.consume(challengeToken, payload.ExpiresAt, now); err != nil {
		return "", err
	}
	return payload.Address, nil
}

// decodeChallengeToken splits and authenticates the token: an unknown
// format, undecodable payload, or bad MAC all answer ErrChallengeInvalid.
func (a *Authenticator) decodeChallengeToken(token string) (challengePayload, error) {
	encodedPayload, encodedMAC, ok := strings.Cut(token, ".")
	if !ok {
		return challengePayload{}, ErrChallengeInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return challengePayload{}, ErrChallengeInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || !hmac.Equal(mac, a.sign(raw)) {
		return challengePayload{}, ErrChallengeInvalid
	}
	var payload challengePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return challengePayload{}, ErrChallengeInvalid
	}
	if payload.ID == "" || payload.Address == "" || payload.Domain == "" || payload.Nonce == "" {
		return challengePayload{}, ErrChallengeInvalid
	}
	return payload, nil
}

// consume records the token in the replay set under one lock, so two
// concurrent verifications of the same token cannot both succeed. Expired
// entries are dropped first; at the cap the earliest-expiring entry is
// evicted, which legitimate traffic never approaches (issue #530).
func (a *Authenticator) consume(token string, expiresAt, now time.Time) error {
	digest := sha256.Sum256([]byte(token))
	id := string(digest[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.consumed[id]; ok {
		return ErrChallengeNotFound
	}
	a.consumed[id] = expiresAt
	a.cleanupExpiredLocked(now)
	for len(a.consumed) >= consumedMax {
		a.evictEarliestLocked()
	}
	return nil
}

func (a *Authenticator) cleanupExpiredLocked(now time.Time) {
	for id, expiresAt := range a.consumed {
		if now.After(expiresAt) {
			delete(a.consumed, id)
		}
	}
}

func (a *Authenticator) evictEarliestLocked() {
	var earliestKey string
	var earliest time.Time
	first := true
	for id, expiresAt := range a.consumed {
		if first || expiresAt.Before(earliest) {
			earliestKey, earliest, first = id, expiresAt, false
		}
	}
	if !first {
		delete(a.consumed, earliestKey)
	}
}

// AddressAllowed reports whether address may authenticate.
func (a *Authenticator) AddressAllowed(address string) bool {
	if a == nil {
		return false
	}
	if a.allowAny {
		return true
	}
	_, ok := a.allowed[strings.ToLower(strings.TrimSpace(address))]
	return ok
}

func (a *Authenticator) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
