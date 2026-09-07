package auth

import (
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const reverseAccessTokenAudience = "portal-ivnp-reverse"

type ReverseAccessTokenClaims struct {
	jwt.Claims
	Identity           types.Identity `json:"identity"`
	IngressDestination string         `json:"ingress_destination"`
	GatewayDestination string         `json:"gateway_destination"`
}

func IssueReverseAccessToken(authority identity.Authority, issuer string, leaseIdentity types.Identity, ingressDestination, gatewayDestination string, ttl time.Duration) (string, ReverseAccessTokenClaims, error) {
	if authority == nil {
		return "", ReverseAccessTokenClaims{}, errors.New("reverse token signing authority is required")
	}
	normalizedIdentity, err := identity.NormalizeIdentity(leaseIdentity)
	if err != nil {
		return "", ReverseAccessTokenClaims{}, err
	}
	ingressDestination, err = utils.NormalizeIVNPDestination(ingressDestination)
	if err != nil {
		return "", ReverseAccessTokenClaims{}, err
	}
	gatewayDestination, err = utils.NormalizeIVNPDestination(gatewayDestination)
	if err != nil {
		return "", ReverseAccessTokenClaims{}, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: leaseTokenAlgorithm,
		Key:       &es256kOpaqueSigner{authority: authority},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", ReverseAccessTokenClaims{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := ReverseAccessTokenClaims{
		Claims: jwt.Claims{
			Issuer:    strings.TrimSpace(issuer),
			Subject:   normalizedIdentity.Key(),
			Audience:  jwt.Audience{reverseAccessTokenAudience},
			ID:        utils.RandomID("rev_"),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiresAt),
		},
		Identity:           normalizedIdentity,
		IngressDestination: ingressDestination,
		GatewayDestination: gatewayDestination,
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", ReverseAccessTokenClaims{}, err
	}
	return token, claims, nil
}

func VerifyReverseAccessToken(token, publicKeyHex, issuer, ingressDestination, peerDestination string, now time.Time) (ReverseAccessTokenClaims, error) {
	publicKey, err := identity.ParseSecp256k1PublicKeyHex(publicKeyHex)
	if err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	parsed, err := jwt.ParseSigned(strings.TrimSpace(token), []jose.SignatureAlgorithm{leaseTokenAlgorithm})
	if err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	var claims ReverseAccessTokenClaims
	if err := parsed.Claims(&es256kOpaqueVerifier{publicKey: publicKey}, &claims); err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	normalizedIdentity, err := identity.NormalizeIdentity(claims.Identity)
	if err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	if normalizedIdentity.Key() != claims.Subject {
		return ReverseAccessTokenClaims{}, errors.New("reverse token identity does not match subject")
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      strings.TrimSpace(issuer),
		AnyAudience: jwt.Audience{reverseAccessTokenAudience},
		Time:        now.UTC(),
	}, 0); err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	claims.IngressDestination, err = utils.NormalizeIVNPDestination(claims.IngressDestination)
	if err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	claims.GatewayDestination, err = utils.NormalizeIVNPDestination(claims.GatewayDestination)
	if err != nil {
		return ReverseAccessTokenClaims{}, err
	}
	wantIngress, err := utils.NormalizeIVNPDestination(ingressDestination)
	if err != nil || claims.IngressDestination != wantIngress {
		return ReverseAccessTokenClaims{}, errors.New("reverse token ingress destination mismatch")
	}
	peerDestination, err = utils.NormalizeIVNPDestination(peerDestination)
	if err != nil || claims.GatewayDestination != peerDestination {
		return ReverseAccessTokenClaims{}, errors.New("reverse token peer destination mismatch")
	}
	claims.Identity = normalizedIdentity
	return claims, nil
}
