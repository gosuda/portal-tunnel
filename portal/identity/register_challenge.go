package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

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
}

func NewRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string, now time.Time, ttl time.Duration) (*RegisterChallenge, error) {
	normalizedIdentity, err := NormalizeIdentity(req.Identity)
	if err != nil {
		return nil, err
	}

	challengeID := utils.RandomID("rch_")
	expiresAt := now.UTC().Add(ttl)
	message, err := FormatSIWEMessage(SIWEMessage{
		Domain: domain, Address: normalizedIdentity.Address, URI: uri,
		Statement: "Register a portal lease", Nonce: rand.Text(), RequestID: challengeID,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("build siwe message: %w", err)
	}

	req.Identity = normalizedIdentity
	req.Metadata = req.Metadata.Copy()

	return &RegisterChallenge{
		ChallengeID: challengeID,
		ExpiresAt:   expiresAt,
		Request:     req,
		SIWEMessage: message,
	}, nil
}

func (c *RegisterChallenge) Expired(now time.Time) bool {
	return c == nil || now.After(c.ExpiresAt)
}

func (c *RegisterChallenge) Verify(req types.RegisterRequest, now time.Time) error {
	if c == nil {
		return ErrRegisterChallengeNotFound
	}
	if req.SIWEMessage != c.SIWEMessage {
		return errors.New("siwe message does not match register challenge")
	}
	if err := VerifySIWEMessage(c.SIWEMessage, req.SIWESignature, c.Request.Identity.Address, c.ExpiresAt, now); err != nil {
		return ErrRegisterChallengeInvalidSignature
	}
	return nil
}
