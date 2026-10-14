package sdk

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	maxRegisterSIWEMessageBytes = 4 << 10
	maxRegisterSIWETimeSkew     = time.Minute
	maxRegisterSIWELifetime     = 5 * time.Minute
)

var errInvalidRegisterSIWEChallenge = errors.New("relay returned an invalid registration SIWE challenge")

// validateRegisterSIWEChallenge binds a relay challenge to the SDK's signing
// purpose, relying party, identity, and destination before personal signing.
// Only the challenge ID, nonce, and timing values come from the relay.
func validateRegisterSIWEChallenge(challenge types.RegisterChallengeResponse, relayURL *url.URL, address string, now time.Time) error {
	if challenge.ChallengeID == "" || !now.Before(challenge.ExpiresAt) {
		return errors.New("relay returned an invalid or expired registration challenge")
	}
	if invalidRegisterRelayURL(relayURL) || len(challenge.SIWEMessage) > maxRegisterSIWEMessageBytes {
		return errInvalidRegisterSIWEChallenge
	}

	// Portal's formatter has twelve lines. Extract only the two relay-selected
	// values; regenerate all other fields from trusted client context.
	lines := strings.Split(challenge.SIWEMessage, "\n")
	if len(lines) != 12 {
		return errInvalidRegisterSIWEChallenge
	}
	nonce, ok := strings.CutPrefix(lines[8], "Nonce: ")
	if !ok {
		return errInvalidRegisterSIWEChallenge
	}
	issuedAtText, ok := strings.CutPrefix(lines[9], "Issued At: ")
	if !ok {
		return errInvalidRegisterSIWEChallenge
	}
	issuedAt, err := time.Parse(time.RFC3339, issuedAtText)
	if err != nil {
		return errInvalidRegisterSIWEChallenge
	}
	expiresAt := challenge.ExpiresAt.Truncate(time.Second)
	if issuedAt.After(now.Add(maxRegisterSIWETimeSkew)) ||
		expiresAt.Before(issuedAt) ||
		expiresAt.Sub(issuedAt) > maxRegisterSIWELifetime ||
		expiresAt.After(now.Add(maxRegisterSIWELifetime)) {
		return errInvalidRegisterSIWEChallenge
	}

	registerURI := (&url.URL{Scheme: relayURL.Scheme, Host: relayURL.Host, Path: types.PathSDKRegister}).String()
	expected, err := identity.FormatSIWEMessage(identity.SIWEMessage{
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
		return errInvalidRegisterSIWEChallenge
	}
	return nil
}

// invalidRegisterRelayURL reports whether the relay URL is missing or shaped
// in a way the SDK must not trust for challenge binding: no host, embedded
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
