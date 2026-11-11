package overlay

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func normalizeIVNPDestination(destination string) (string, error) {
	destination = strings.ToLower(strings.TrimSpace(destination))
	label, ok := strings.CutSuffix(destination, ".b32.i2p")
	if !ok || len(label) != 52 {
		return "", errIvnpDestinationMust32ByteB32
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := encoding.DecodeString(strings.ToUpper(label))
	if err != nil || len(raw) != 32 || strings.ToLower(encoding.EncodeToString(raw)) != label {
		return "", errInvalidIvnpDestinationHash
	}
	return destination, nil
}

func (r *Runtime) Handles(capability string) bool {
	return strings.HasPrefix(strings.TrimSpace(capability), types.OverlayCapabilityPrefix+".")
}

type capabilityClaims struct {
	Version            int                   `json:"version"`
	LeaseIdentity      types.Identity        `json:"lease_identity"`
	LeaseID            string                `json:"lease_id"`
	ExpiresAt          time.Time             `json:"expires_at"`
	Ingress            types.RelayDescriptor `json:"ingress"`
	GatewayAddress     string                `json:"gateway_address"`
	GatewayDestination string                `json:"gateway_destination"`
}

func signCapability(authority identity.Authority, claims capabilityClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signature, err := authority.SignSHA256Secp256k1(payload)
	if err != nil {
		return "", err
	}
	compact, err := signature.Compact()
	if err != nil {
		return "", err
	}
	return types.OverlayCapabilityPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(compact), nil
}

func verifyCapability(capability string, now time.Time) (capabilityClaims, error) {
	payload, signature, err := verifyCapabilityPayload(capability)
	if err != nil {
		return capabilityClaims{}, err
	}
	claims, err := verifyCapabilityUnmarshal(payload)
	if err != nil {
		return capabilityClaims{}, err
	}
	return verifyCapabilityAttest(claims, payload, signature, now)
}

func verifyCapabilityPayload(capability string) ([]byte, []byte, error) {
	capability = strings.TrimSpace(capability)
	if len(capability) == 0 || len(capability) > capabilityLimit {
		return nil, nil, errInvalidOverlayCapabilityLength
	}
	parts := strings.Split(capability, ".")
	if len(parts) != 3 || parts[0] != types.OverlayCapabilityPrefix {
		return nil, nil, errInvalidOverlayCapability
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > capabilityLimit {
		return nil, nil, errInvalidOverlayCapabilityPayload
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, errInvalidOverlayCapabilitySignature
	}
	return payload, signature, nil
}

func verifyCapabilityUnmarshal(payload []byte) (capabilityClaims, error) {
	var claims capabilityClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return capabilityClaims{}, errInvalidOverlayCapabilityClaims
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return capabilityClaims{}, errInvalidOverlayCapabilityClaims
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, payload) {
		return capabilityClaims{}, errNonCanonicalOverlayCapability
	}
	return claims, nil
}

func verifyCapabilityAttest(claims capabilityClaims, payload []byte, signature []byte, now time.Time) (capabilityClaims, error) {
	verifiedIngress, err := discovery.VerifyRelayDescriptor(claims.Ingress)
	if err != nil {
		return capabilityClaims{}, err
	}
	verifiedIngress.IVNPDestination, err = normalizeIVNPDestination(verifiedIngress.IVNPDestination)
	if err != nil {
		return capabilityClaims{}, err
	}
	publicKey, err := identity.RecoverSHA256Secp256k1Compact(payload, signature)
	if err != nil {
		return capabilityClaims{}, err
	}
	address, err := identity.AddressFromCompressedPublicKeyHex(hex.EncodeToString(publicKey.SerializeCompressed()))
	if err != nil || !strings.EqualFold(address, verifiedIngress.Address) {
		return capabilityClaims{}, errOverlayCapabilitySignerDoesNotMatch
	}
	claims.LeaseID = strings.TrimSpace(claims.LeaseID)
	claims.GatewayAddress = strings.TrimSpace(claims.GatewayAddress)
	claims.GatewayDestination, err = normalizeIVNPDestination(claims.GatewayDestination)
	incomplete := claims.Version != 1 || claims.LeaseID == "" || claims.GatewayAddress == ""
	invalidExpiry := !claims.ExpiresAt.After(now) || claims.ExpiresAt.After(verifiedIngress.ExpiresAt)
	if err != nil || incomplete || invalidExpiry {
		return capabilityClaims{}, errOverlayCapabilityExpiredOrIncomplete
	}
	claims.Ingress = verifiedIngress
	return claims, nil
}
