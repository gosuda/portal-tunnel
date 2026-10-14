package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	maxRegisterSIWEMessageBytes = 4 << 10
	maxRegisterSIWETimeSkew     = time.Minute
	maxRegisterSIWELifetime     = 5 * time.Minute
)

var (
	ErrRegisterChallengeExpired          = errors.New("register challenge expired")
	ErrRegisterChallengeNotFound         = errors.New("register challenge not found")
	ErrRegisterChallengeInvalidSignature = errors.New("siwe signature is invalid")
	ErrInvalidRegisterSIWEChallenge      = errors.New("relay returned an invalid registration SIWE challenge")
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
		Statement: types.RegisterLeaseSIWEStatement, Nonce: rand.Text(), RequestID: challengeID,
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

// ValidateRegisterSIWEChallenge binds a relay challenge to the registration signing
// purpose, relying party, identity, and destination before personal signing.
// Only the challenge ID, nonce, and timing values come from the relay.
func ValidateRegisterSIWEChallenge(challenge types.RegisterChallengeResponse, relayURL *url.URL, address string, now time.Time) error {
	if challenge.ChallengeID == "" || !now.Before(challenge.ExpiresAt) {
		return errors.New("relay returned an invalid or expired registration challenge")
	}
	if invalidRegisterRelayURL(relayURL) || len(challenge.SIWEMessage) > maxRegisterSIWEMessageBytes {
		return ErrInvalidRegisterSIWEChallenge
	}

	// Portal's formatter has twelve lines. Extract only the two relay-selected
	// values; regenerate all other fields from trusted client context.
	lines := strings.Split(challenge.SIWEMessage, "\n")
	if len(lines) != 12 {
		return ErrInvalidRegisterSIWEChallenge
	}
	nonce, ok := strings.CutPrefix(lines[8], "Nonce: ")
	if !ok {
		return ErrInvalidRegisterSIWEChallenge
	}
	issuedAtText, ok := strings.CutPrefix(lines[9], "Issued At: ")
	if !ok {
		return ErrInvalidRegisterSIWEChallenge
	}
	issuedAt, err := time.Parse(time.RFC3339, issuedAtText)
	if err != nil {
		return ErrInvalidRegisterSIWEChallenge
	}
	expiresAt := challenge.ExpiresAt.Truncate(time.Second)
	if issuedAt.After(now.Add(maxRegisterSIWETimeSkew)) ||
		expiresAt.Before(issuedAt) ||
		expiresAt.Sub(issuedAt) > maxRegisterSIWELifetime ||
		expiresAt.After(now.Add(maxRegisterSIWELifetime)) {
		return ErrInvalidRegisterSIWEChallenge
	}

	registerURI := (&url.URL{Scheme: relayURL.Scheme, Host: relayURL.Host, Path: types.PathSDKRegister}).String()
	expected, err := FormatSIWEMessage(SIWEMessage{
		Domain:    relayURL.Host,
		Address:   address,
		URI:       registerURI,
		Statement: types.RegisterLeaseSIWEStatement,
		Nonce:     nonce,
		RequestID: challenge.ChallengeID,
		IssuedAt:  issuedAt,
		ExpiresAt: challenge.ExpiresAt,
	})
	if err != nil || expected != challenge.SIWEMessage {
		return ErrInvalidRegisterSIWEChallenge
	}
	return nil
}

// invalidRegisterRelayURL reports whether the relay URL is missing or shaped
// in a way that cannot be trusted for challenge binding: no host, embedded
// credentials, or a non-HTTP scheme.
func invalidRegisterRelayURL(relayURL *url.URL) bool {
	if relayURL == nil || relayURL.Hostname() == "" {
		return true
	}
	if relayURL.User != nil {
		return true
	}
	return relayURL.Scheme != "https" && relayURL.Scheme != "http"
}
