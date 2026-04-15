package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	leaseAccessTokenAudience = "portal-sdk"
	leaseTokenAlgorithm      = jose.SignatureAlgorithm("ES256K")
)

type LeaseAccessTokenClaims struct {
	jwt.Claims
	Identity types.Identity `json:"identity"`
}

type es256kOpaqueSigner struct {
	keyID      string
	privateKey *secp256k1.PrivateKey
}

func (s *es256kOpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{KeyID: s.keyID}
}

func (s *es256kOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{leaseTokenAlgorithm}
}

func (s *es256kOpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != leaseTokenAlgorithm {
		return nil, jose.ErrUnsupportedAlgorithm
	}
	if s == nil || s.privateKey == nil {
		return nil, errors.New("signing key is required")
	}
	return utils.SignSHA256Secp256k1Raw64(payload, s.privateKey)
}

type es256kOpaqueVerifier struct {
	publicKey *secp256k1.PublicKey
}

func (v *es256kOpaqueVerifier) VerifyPayload(payload []byte, signature []byte, alg jose.SignatureAlgorithm) error {
	if alg != leaseTokenAlgorithm {
		return jose.ErrUnsupportedAlgorithm
	}
	if v == nil || v.publicKey == nil {
		return errors.New("verification key is required")
	}
	if err := utils.VerifySHA256Secp256k1Raw64(payload, signature, v.publicKey); err != nil {
		if errors.Is(err, utils.ErrSecp256k1SignatureInvalid) {
			return errors.New("token signature is invalid")
		}
		return err
	}
	return nil
}

func IssueLeaseAccessToken(privateKeyHex, keyID, issuer string, identity types.Identity, ttl time.Duration) (string, LeaseAccessTokenClaims, error) {
	privateKey, _, err := utils.ParseSecp256k1PrivateKeyHex(privateKeyHex, false)
	if err != nil {
		return "", LeaseAccessTokenClaims{}, err
	}
	normalizedIdentity, err := utils.NormalizeIdentity(identity)
	if err != nil {
		return "", LeaseAccessTokenClaims{}, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: leaseTokenAlgorithm,
		Key: &es256kOpaqueSigner{
			keyID:      strings.TrimSpace(keyID),
			privateKey: privateKey,
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
	publicKey, err := utils.ParseSecp256k1PublicKeyHex(publicKeyHex)
	if err != nil {
		return LeaseAccessTokenClaims{}, err
	}

	parsed, err := jwt.ParseSigned(strings.TrimSpace(token), []jose.SignatureAlgorithm{leaseTokenAlgorithm})
	if err != nil {
		return LeaseAccessTokenClaims{}, err
	}

	var claims LeaseAccessTokenClaims
	if err := parsed.Claims(&es256kOpaqueVerifier{publicKey: publicKey}, &claims); err != nil {
		return LeaseAccessTokenClaims{}, err
	}
	normalizedClaimsIdentity, err := utils.NormalizeIdentity(claims.Identity)
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
