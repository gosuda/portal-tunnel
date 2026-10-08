package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
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
	if err != nil || domain.Host == "" {
		return "", errors.New("invalid siwe domain")
	}
	authority := domain.Host
	if domain.User != nil {
		authority = domain.User.String() + "@" + authority
	}
	if authority != m.Domain {
		return "", errors.New("invalid siwe domain")
	}
	uri, err := url.Parse(m.URI)
	if err != nil || !uri.IsAbs() {
		return "", errors.New("invalid siwe uri")
	}
	address, err := NormalizeEVMAddress(m.Address)
	if err != nil {
		return "", err
	}
	if strings.IndexFunc(m.Statement, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
		return "", errors.New("siwe statement must be a single ASCII line")
	}
	invalidNonce := strings.IndexFunc(m.Nonce, func(r rune) bool {
		lower := r >= 'a' && r <= 'z'
		upper := r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		return !lower && !upper && !digit
	}) >= 0
	if len(m.Nonce) < 8 || invalidNonce {
		return "", errors.New("siwe nonce must contain at least 8 alphanumeric characters")
	}
	if strings.ContainsAny(m.RequestID, "\r\n") {
		return "", errors.New("invalid siwe request ID")
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
		return errors.New("siwe message expired")
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
