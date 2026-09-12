package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// siweMessage formats the EIP-4361 fields Portal issues for registration and
// wallet login. Version and chain ID remain 1; this is not a general SIWE parser.
type siweMessage struct {
	domain, address, uri, statement, nonce, requestID string
	issuedAt, expiresAt                               time.Time
}

func (m siweMessage) format() (string, error) {
	domain, err := url.Parse("https://" + m.domain)
	if err != nil || domain.Host == "" {
		return "", errors.New("invalid siwe domain")
	}
	authority := domain.Host
	if domain.User != nil {
		authority = domain.User.String() + "@" + authority
	}
	if authority != m.domain {
		return "", errors.New("invalid siwe domain")
	}
	uri, err := url.Parse(m.uri)
	if err != nil || !uri.IsAbs() {
		return "", errors.New("invalid siwe uri")
	}
	address, err := NormalizeEVMAddress(m.address)
	if err != nil {
		return "", err
	}
	if strings.IndexFunc(m.statement, func(r rune) bool { return r < ' ' || r > '~' }) >= 0 {
		return "", errors.New("siwe statement must be a single ASCII line")
	}
	invalidNonce := strings.IndexFunc(m.nonce, func(r rune) bool {
		lower := r >= 'a' && r <= 'z'
		upper := r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		return !lower && !upper && !digit
	}) >= 0
	if len(m.nonce) < 8 || invalidNonce {
		return "", errors.New("siwe nonce must contain at least 8 alphanumeric characters")
	}
	if strings.ContainsAny(m.requestID, "\r\n") {
		return "", errors.New("invalid siwe request ID")
	}

	header := fmt.Sprintf("%s wants you to sign in with your Ethereum account:\n%s\n\n", m.domain, address)
	if m.statement != "" {
		header += m.statement + "\n"
	}
	return fmt.Sprintf("%s\nURI: %s\nVersion: 1\nChain ID: 1\nNonce: %s\nIssued At: %s\nExpiration Time: %s\nRequest ID: %s",
		header, uri.String(), m.nonce, m.issuedAt.UTC().Format(time.RFC3339), m.expiresAt.UTC().Format(time.RFC3339), m.requestID), nil
}

// verifySIWEMessage verifies the stored challenge, after the caller has matched
// the submitted message byte-for-byte. Domain, nonce and request ID are bound by
// that message; parsing them back out would create a second validation path.
func verifySIWEMessage(message, signature, address string, expiresAt, now time.Time) error {
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
