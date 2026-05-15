package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func ensureTokenSecret(identity types.Identity) (types.Identity, error) {
	identity = identity.Copy()
	identity.TokenSecret = strings.TrimSpace(identity.TokenSecret)
	if identity.TokenSecret != "" {
		return identity, nil
	}

	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return types.Identity{}, fmt.Errorf("generate token secret: %w", err)
	}
	identity.TokenSecret = base64.RawURLEncoding.EncodeToString(secret[:])
	return identity, nil
}

// DeriveToken derives a deterministic identity-scoped token from ordered
// length-prefixed token parts. The first part should identify the token family.
func DeriveToken(identity types.Identity, parts ...string) (string, error) {
	tokenSecret := strings.TrimSpace(identity.TokenSecret)
	if tokenSecret == "" {
		return "", errors.New("identity token secret is required")
	}

	mac := hmac.New(sha256.New, []byte(tokenSecret))
	_, _ = mac.Write([]byte("Portal identity token v1\n"))
	_, _ = mac.Write([]byte(identity.Key()))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		_, _ = mac.Write([]byte("\n"))
		_, _ = mac.Write([]byte(strconv.Itoa(len(part))))
		_, _ = mac.Write([]byte(":"))
		_, _ = mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
