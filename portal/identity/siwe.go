package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	errInvalidSIWEDomain                = errors.New("invalid siwe domain")
	errInvalidSIWEURI                   = errors.New("invalid siwe uri")
	errSIWEStatementMustSingleAsciiLine = errors.New("siwe statement must be a single ASCII line")
	errSIWENonceMustContainLeast8       = errors.New("siwe nonce must contain at least 8 alphanumeric characters")
	errInvalidSIWERequestID             = errors.New("invalid siwe request ID")
	errSIWEMessageExpired               = errors.New("siwe message expired")
)

const (
	siweVersion = "1"
	siweChainID = 1
)

type SIWEMessage struct {
	Domain    string
	Address   string
	URI       string
	Statement string
	Nonce     string
	RequestID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// FormatSIWEMessage formats the EIP-4361 subset Portal issues for registration
// and wallet login. It is not a general SIWE formatter.
func FormatSIWEMessage(m SIWEMessage) (string, error) {
	domain, err := url.Parse("https://" + m.Domain)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errInvalidSIWEDomain, err)
	}
	if domain.Host == "" {
		return "", errInvalidSIWEDomain
	}
	authority := domain.Host
	if domain.User != nil {
		authority = domain.User.String() + "@" + authority
	}
	if authority != m.Domain {
		return "", errInvalidSIWEDomain
	}
	uri, err := url.Parse(m.URI)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errInvalidSIWEURI, err)
	}
	if !uri.IsAbs() {
		return "", errInvalidSIWEURI
	}
	address, err := NormalizeEVMAddress(m.Address)
	if err != nil {
		return "", err
	}
	if strings.IndexFunc(m.Statement, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
		return "", errSIWEStatementMustSingleAsciiLine
	}
	invalidNonce := strings.IndexFunc(m.Nonce, func(r rune) bool {
		lower := r >= 'a' && r <= 'z'
		upper := r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		return !lower && !upper && !digit
	}) >= 0
	if len(m.Nonce) < 8 || invalidNonce {
		return "", errSIWENonceMustContainLeast8
	}
	if strings.ContainsAny(m.RequestID, "\r\n") {
		return "", errInvalidSIWERequestID
	}

	header := fmt.Sprintf("%s wants you to sign in with your Ethereum account:\n%s\n\n", m.Domain, address)
	if m.Statement != "" {
		header += m.Statement + "\n"
	}
	return fmt.Sprintf("%s\nURI: %s\nVersion: %s\nChain ID: %d\nNonce: %s\nIssued At: %s\nExpiration Time: %s\nRequest ID: %s",
		header, uri.String(), siweVersion, siweChainID, m.Nonce, m.IssuedAt.UTC().Format(time.RFC3339), m.ExpiresAt.UTC().Format(time.RFC3339), m.RequestID), nil
}

// VerifySIWEMessage verifies the stored challenge after the caller has matched
// the submitted message byte-for-byte. Domain, nonce and request ID are bound by
// that message; parsing them back out would create a second validation path.
func VerifySIWEMessage(message, signature, address string, expiresAt, now time.Time) error {
	// The signed RFC3339 expiration has second precision. Preserve the existing
	// inclusive cutoff even when the stored challenge timestamp has nanoseconds.
	if now.After(expiresAt.Truncate(time.Second)) {
		return errSIWEMessageExpired
	}
	signer, err := recoverEthereumPersonalMessage(message, signature)
	if err != nil {
		return err
	}
	if !strings.EqualFold(signer, address) {
		return ErrSecp256k1SignatureInvalid
	}
	return nil
}
