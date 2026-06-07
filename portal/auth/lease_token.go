package auth

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	leaseAccessTokenAudience = "portal-sdk"
	leaseTokenAlgorithm      = jose.EdDSA
)

type LeaseAccessTokenClaims struct {
	jwt.Claims
	Identity types.Identity `json:"identity"`
}

type ed25519OpaqueSigner struct {
	authority identity.Authority
}

func (s *ed25519OpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{}
}

func (s *ed25519OpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{leaseTokenAlgorithm}
}

func (s *ed25519OpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != leaseTokenAlgorithm {
		return nil, jose.ErrUnsupportedAlgorithm
	}
	if s == nil || s.authority == nil {
		return nil, errors.New("signing key is required")
	}
	signatureHex, err := s.authority.SignEd25519(payload)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(signatureHex)
}

type ed25519OpaqueVerifier struct {
	publicKey string
}

func (v *ed25519OpaqueVerifier) VerifyPayload(payload []byte, signature []byte, alg jose.SignatureAlgorithm) error {
	if alg != leaseTokenAlgorithm {
		return jose.ErrUnsupportedAlgorithm
	}
	if v == nil || strings.TrimSpace(v.publicKey) == "" {
		return errors.New("verification key is required")
	}
	if err := identity.VerifyEd25519Hex(payload, v.publicKey, hex.EncodeToString(signature)); err != nil {
		return errors.New("token signature is invalid")
	}
	return nil
}

func IssueLeaseAccessToken(authority identity.Authority, issuer string, leaseIdentity types.Identity, ttl time.Duration) (string, LeaseAccessTokenClaims, error) {
	if authority == nil {
		return "", LeaseAccessTokenClaims{}, errors.New("lease token signing authority is required")
	}
	normalizedIdentity, err := identity.NormalizeIdentity(leaseIdentity)
	if err != nil {
		return "", LeaseAccessTokenClaims{}, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: leaseTokenAlgorithm,
		Key: &ed25519OpaqueSigner{
			authority: authority,
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", LeaseAccessTokenClaims{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := LeaseAccessTokenClaims{
		Claims: jwt.Claims{
			Issuer:    strings.TrimSpace(issuer),
			Subject:   normalizedIdentity.Key(),
			Audience:  jwt.Audience{leaseAccessTokenAudience},
			ID:        utils.RandomID("tok_"),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiresAt),
		},
		Identity: normalizedIdentity,
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", LeaseAccessTokenClaims{}, err
	}
	return token, claims, nil
}

func VerifyLeaseAccessToken(token, publicKeyHex, issuer string, now time.Time) (LeaseAccessTokenClaims, error) {
	parsed, err := jwt.ParseSigned(strings.TrimSpace(token), []jose.SignatureAlgorithm{leaseTokenAlgorithm})
	if err != nil {
		return LeaseAccessTokenClaims{}, err
	}

	var claims LeaseAccessTokenClaims
	if err := parsed.Claims(&ed25519OpaqueVerifier{publicKey: publicKeyHex}, &claims); err != nil {
		return LeaseAccessTokenClaims{}, err
	}
	normalizedClaimsIdentity, err := identity.NormalizeIdentity(claims.Identity)
	if err != nil {
		return LeaseAccessTokenClaims{}, err
	}
	if normalizedClaimsIdentity.Key() != claims.Subject {
		return LeaseAccessTokenClaims{}, errors.New("lease access token identity does not match subject")
	}
	claims.Identity = normalizedClaimsIdentity
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      strings.TrimSpace(issuer),
		AnyAudience: jwt.Audience{leaseAccessTokenAudience},
		Time:        now.UTC(),
	}, 0); err != nil {
		return LeaseAccessTokenClaims{}, err
	}
	return claims, nil
}
