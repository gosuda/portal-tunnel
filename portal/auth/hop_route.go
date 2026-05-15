package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var ErrHopRouteSignatureInvalid = errors.New("hop route signature is invalid")

func normalizeHopRoute(route *types.HopRoute, requireOwner bool) error {
	ownerPublicKey := strings.ToLower(utils.TrimHexPrefix(strings.TrimSpace(route.OwnerPublicKey)))
	if ownerPublicKey != "" {
		if _, err := identity.ParseSecp256k1PublicKeyHex(ownerPublicKey); err != nil {
			return fmt.Errorf("hop route owner public key: %w", err)
		}
	} else if requireOwner {
		return errors.New("hop route owner public key is required")
	}

	relayURL, err := utils.NormalizeRelayURL(route.RelayURL)
	if err != nil {
		return fmt.Errorf("hop relay url: %w", err)
	}

	route.OwnerPublicKey = ownerPublicKey
	route.RelayURL = relayURL
	route.PublicHostname = utils.NormalizeHostname(route.PublicHostname)
	route.RouteHostname = utils.NormalizeHostname(route.RouteHostname)
	route.HostnameHash = strings.TrimSpace(route.HostnameHash)
	route.MatchToken = strings.TrimSpace(route.MatchToken)
	route.Metadata = route.Metadata.Copy()
	route.ForwardToken = strings.TrimSpace(route.ForwardToken)
	route.ExpiresAt = route.ExpiresAt.UTC()
	route.Signature = strings.TrimSpace(route.Signature)
	return nil
}

func SignHopRoute(method string, route types.HopRoute, authority identity.Authority, expiresAt time.Time) (types.HopRoute, error) {
	if authority == nil {
		return types.HopRoute{}, errors.New("hop route signing authority is required")
	}
	route.ExpiresAt = expiresAt.UTC()
	route.Signature = ""
	route.OwnerPublicKey = ""

	if err := normalizeHopRoute(&route, false); err != nil {
		return types.HopRoute{}, err
	}
	ownerIdentity := authority.Identity()
	ownerPublicKey := strings.ToLower(utils.TrimHexPrefix(strings.TrimSpace(ownerIdentity.PublicKey)))
	if ownerPublicKey == "" {
		return types.HopRoute{}, errors.New("hop route owner identity is required")
	}
	if _, err := identity.ParseSecp256k1PublicKeyHex(ownerPublicKey); err != nil {
		return types.HopRoute{}, fmt.Errorf("hop route owner public key: %w", err)
	}

	route.OwnerPublicKey = ownerPublicKey
	payload, err := types.HopRouteBytes(method, route)
	if err != nil {
		return types.HopRoute{}, err
	}
	signature, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		return types.HopRoute{}, err
	}
	route.Signature, err = signature.DERHex()
	if err != nil {
		return types.HopRoute{}, err
	}
	return route, nil
}

func VerifyHopRoute(method string, route types.HopRoute) (types.HopRoute, error) {
	signature := strings.TrimSpace(route.Signature)
	route.Signature = ""

	if err := normalizeHopRoute(&route, true); err != nil {
		return types.HopRoute{}, err
	}
	payload, err := types.HopRouteBytes(method, route)
	if err != nil {
		return types.HopRoute{}, err
	}
	if err := identity.VerifySHA256Secp256k1DER(payload, route.OwnerPublicKey, signature); err != nil {
		return types.HopRoute{}, ErrHopRouteSignatureInvalid
	}
	route.Signature = signature
	return route, nil
}
