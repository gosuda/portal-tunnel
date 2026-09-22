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
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	siweAuthChallengeTTL = 2 * time.Minute
	siweAuthChallengeMax = 4096
)

var (
	errSIWEAuthUnauthorized      = errors.New("wallet is not allowed")
	errSIWEAuthChallengeNotFound = errors.New("wallet auth challenge not found")
	errSIWEAuthChallengeExpired  = errors.New("wallet auth challenge expired")
	errSIWEAuthInvalidSignature  = errors.New("wallet auth signature is invalid")
	errSIWEAuthTooManyChallenges = errors.New("too many pending wallet auth challenges")
)

type siweAuthConfig struct {
	AllowedAddresses []string
	AllowAnyAddress  bool
	Statement        string
	ChallengePrefix  string
}

type siweAuthenticator struct {
	allowed         map[string]struct{}
	allowAny        bool
	statement       string
	challengePrefix string

	mu         sync.Mutex
	challenges map[string]siweAuthChallenge
}

type siweAuthChallenge struct {
	ID        string
	Address   string
	Domain    string
	Message   string
	ExpiresAt time.Time
}

func newSIWEAuthenticator(cfg siweAuthConfig) (*siweAuthenticator, error) {
	addresses, err := normalizeSIWEAuthAddresses(cfg.AllowedAddresses)
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
	return &siweAuthenticator{
		allowed:         allowed,
		allowAny:        cfg.AllowAnyAddress,
		statement:       cmp.Or(strings.TrimSpace(cfg.Statement), "Sign in to Portal"),
		challengePrefix: strings.TrimSpace(cfg.ChallengePrefix),
		challenges:      make(map[string]siweAuthChallenge),
	}, nil
}

func normalizeSIWEAuthAddresses(values []string) ([]string, error) {
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

func (a *siweAuthenticator) Issue(address, domain, uri string, now time.Time) (siweAuthChallenge, error) {
	if a == nil {
		return siweAuthChallenge{}, errSIWEAuthUnauthorized
	}
	address, err := identity.NormalizeEVMAddress(address)
	if err != nil {
		return siweAuthChallenge{}, err
	}
	if !a.addressAllowed(address) {
		return siweAuthChallenge{}, errSIWEAuthUnauthorized
	}

	now = now.UTC()
	challenge := siweAuthChallenge{
		ID:        utils.RandomID(a.challengePrefix),
		Address:   address,
		Domain:    strings.TrimSpace(domain),
		ExpiresAt: now.Add(siweAuthChallengeTTL),
	}
	challenge.Message, err = identity.FormatSIWEMessage(identity.SIWEMessage{
		Domain: challenge.Domain, Address: address, URI: uri,
		Statement: a.statement, Nonce: rand.Text(), RequestID: challenge.ID,
		IssuedAt: now, ExpiresAt: challenge.ExpiresAt,
	})
	if err != nil {
		return siweAuthChallenge{}, fmt.Errorf("build wallet auth message: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupExpiredLocked(now)
	if len(a.challenges) >= siweAuthChallengeMax {
		return siweAuthChallenge{}, errSIWEAuthTooManyChallenges
	}
	a.challenges[challenge.ID] = challenge
	return challenge, nil
}

func (a *siweAuthenticator) Verify(challengeID, message, signature, domain string, now time.Time) (string, error) {
	if a == nil {
		return "", errSIWEAuthUnauthorized
	}
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return "", errSIWEAuthChallengeNotFound
	}
	now = now.UTC()

	a.mu.Lock()
	challenge, ok := a.challenges[challengeID]
	delete(a.challenges, challengeID)
	a.cleanupExpiredLocked(now)
	a.mu.Unlock()
	if !ok {
		return "", errSIWEAuthChallengeNotFound
	}
	if now.After(challenge.ExpiresAt) {
		return "", errSIWEAuthChallengeExpired
	}
	if !strings.EqualFold(challenge.Domain, strings.TrimSpace(domain)) || message != challenge.Message {
		return "", errSIWEAuthInvalidSignature
	}
	if err := identity.VerifySIWEMessage(challenge.Message, signature, challenge.Address, challenge.ExpiresAt, now); err != nil {
		return "", errSIWEAuthInvalidSignature
	}
	if !a.addressAllowed(challenge.Address) {
		return "", errSIWEAuthUnauthorized
	}
	return challenge.Address, nil
}

func (a *siweAuthenticator) addressAllowed(address string) bool {
	if a == nil {
		return false
	}
	if a.allowAny {
		return true
	}
	_, ok := a.allowed[strings.ToLower(strings.TrimSpace(address))]
	return ok
}

func (a *siweAuthenticator) cleanupExpiredLocked(now time.Time) {
	for id, challenge := range a.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(a.challenges, id)
		}
	}
}
