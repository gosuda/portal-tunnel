package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spruceid/siwe-go"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	ErrRegisterChallengeExpired          = errors.New("register challenge expired")
	ErrRegisterChallengeNotFound         = errors.New("register challenge not found")
	ErrRegisterChallengeInvalidSignature = errors.New("siwe signature is invalid")
)

type RegisterChallenge struct {
	ChallengeID string
	ExpiresAt   time.Time
	Request     types.RegisterChallengeRequest
	SIWEMessage string

	domain string
	nonce  string
}

func NewRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string, now time.Time, ttl time.Duration) (*RegisterChallenge, error) {
	normalizedIdentity, err := utils.NormalizeIdentity(req.Identity)
	if err != nil {
		return nil, err
	}

	challengeID := utils.RandomID("rch_")
	nonce := siwe.GenerateNonce()
	expiresAt := now.UTC().Add(ttl)
	message, err := siwe.InitMessage(domain, normalizedIdentity.Address, uri, nonce, map[string]interface{}{
		"statement":      "Register a portal lease",
		"chainId":        1,
		"issuedAt":       now.UTC().Format(time.RFC3339),
		"expirationTime": expiresAt.UTC().Format(time.RFC3339),
		"requestId":      challengeID,
	})
	if err != nil {
		return nil, fmt.Errorf("build siwe message: %w", err)
	}

	normalizedRequest := types.RegisterChallengeRequest{
		Identity:   normalizedIdentity,
		Metadata:   req.Metadata.Copy(),
		TTL:        req.TTL,
		UDPEnabled: req.UDPEnabled,
		TCPEnabled: req.TCPEnabled,
	}

	return &RegisterChallenge{
		ChallengeID: challengeID,
		ExpiresAt:   expiresAt,
		Request:     normalizedRequest,
		SIWEMessage: message.String(),
		domain:      strings.TrimSpace(domain),
		nonce:       nonce,
	}, nil
}

func (c *RegisterChallenge) Expired(now time.Time) bool {
	return c == nil || now.After(c.ExpiresAt)
}

func (c *RegisterChallenge) Verify(req types.RegisterRequest, now time.Time) error {
	if c == nil {
		return ErrRegisterChallengeNotFound
	}
	if strings.TrimSpace(req.SIWEMessage) != c.SIWEMessage {
		return errors.New("siwe message does not match register challenge")
	}
	message, err := siwe.ParseMessage(strings.TrimSpace(c.SIWEMessage))
	if err != nil {
		return ErrRegisterChallengeInvalidSignature
	}
	normalizedDomain := strings.TrimSpace(c.domain)
	normalizedNonce := strings.TrimSpace(c.nonce)
	verifiedAt := now.UTC()
	if _, err := message.Verify(strings.TrimSpace(req.SIWESignature), &normalizedDomain, &normalizedNonce, &verifiedAt); err != nil {
		return ErrRegisterChallengeInvalidSignature
	}
	return nil
}
