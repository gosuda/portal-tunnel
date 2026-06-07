package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	ErrRegisterChallengeExpired          = errors.New("register challenge expired")
	ErrRegisterChallengeNotFound         = errors.New("register challenge not found")
	ErrRegisterChallengeInvalidSignature = errors.New("sui signature is invalid")
)

type RegisterChallenge struct {
	ChallengeID string
	ExpiresAt   time.Time
	Request     types.RegisterChallengeRequest
	Message     string
}

func NewRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string, now time.Time, ttl time.Duration) (*RegisterChallenge, error) {
	normalizedIdentity, err := identity.NormalizeIdentity(req.Identity)
	if err != nil {
		return nil, err
	}

	challengeID := utils.RandomID("rch_")
	nonce := utils.RandomID("nonce_")
	expiresAt := now.UTC().Add(ttl)
	message := buildSuiAuthMessage("Register a Portal lease", strings.TrimSpace(domain), strings.TrimSpace(uri), normalizedIdentity.Address, nonce, challengeID, now.UTC(), expiresAt)

	req.Identity = normalizedIdentity
	req.Metadata = req.Metadata.Copy()

	return &RegisterChallenge{
		ChallengeID: challengeID,
		ExpiresAt:   expiresAt,
		Request:     req,
		Message:     message,
	}, nil
}

func (c *RegisterChallenge) Expired(now time.Time) bool {
	return c == nil || now.After(c.ExpiresAt)
}

func (c *RegisterChallenge) Verify(req types.RegisterRequest, now time.Time) error {
	if c == nil {
		return ErrRegisterChallengeNotFound
	}
	if strings.TrimSpace(req.Message) != c.Message {
		return errors.New("message does not match register challenge")
	}
	address, err := identity.VerifySuiPersonalMessageSignature([]byte(c.Message), req.Signature, nil)
	if err != nil {
		return ErrRegisterChallengeInvalidSignature
	}
	if !strings.EqualFold(address, c.Request.Identity.Address) {
		return ErrRegisterChallengeInvalidSignature
	}
	return nil
}
