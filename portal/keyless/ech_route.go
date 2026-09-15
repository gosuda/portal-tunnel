package keyless

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// ECHMaterials is the immutable ECH material for one lease endpoint, prepared
// once from the owning identity. RouteHostname is the opaque outer SNI route,
// HostnameHash validates the public fallback hostname, and Keys/ConfigList
// carry the HPKE key and ECHConfigList for TLS and DNS publication.
type ECHMaterials struct {
	RouteHostname string
	HostnameHash  string
	ConfigList    []byte
	Keys          []tls.EncryptedClientHelloKey
}

// TenantECHMaterials derives the complete tenant ECH material set for a
// lease from the tunnel identity, its public fallback hostname, and the
// relay root hostname.
func TenantECHMaterials(id types.Identity, publicHostname, rootHostname string) (ECHMaterials, error) {
	routeHostname, err := ECHRouteHostname(id, publicHostname, rootHostname)
	if err != nil {
		return ECHMaterials{}, err
	}
	seed, err := identity.DeriveToken(id, "tenant-ech", publicHostname, routeHostname)
	if err != nil {
		return ECHMaterials{}, fmt.Errorf("derive tenant ech seed: %w", err)
	}
	keys, configList, err := EncryptedClientHelloMaterials(seed, routeHostname)
	if err != nil {
		return ECHMaterials{}, fmt.Errorf("prepare tenant ech materials: %w", err)
	}
	return ECHMaterials{
		RouteHostname: routeHostname,
		HostnameHash:  ECHHostnameHash(publicHostname),
		ConfigList:    configList,
		Keys:          keys,
	}, nil
}

// RelayECHMaterials derives the ECH key/config material for the relay's own
// API listener from the relay identity and its persistent ECH seed.
func RelayECHMaterials(id types.Identity, seed, publicName string) ([]tls.EncryptedClientHelloKey, []byte, error) {
	echSeed, err := identity.DeriveToken(id, "relay-ech", seed, publicName)
	if err != nil {
		return nil, nil, fmt.Errorf("derive relay ech seed: %w", err)
	}
	return EncryptedClientHelloMaterials(echSeed, publicName)
}

// ECHRouteHostname derives the opaque ECH route hostname for a tenant lease:
// an identity-derived token is compressed into one DNS label under the relay
// root hostname, hiding the tenant identity from the relay while routing
// ECH connections.
func ECHRouteHostname(id types.Identity, publicHostname, rootHostname string) (string, error) {
	routeToken, err := identity.DeriveToken(id, "ech-route", publicHostname, rootHostname)
	if err != nil {
		return "", err
	}
	routeSum := sha256.Sum256([]byte(routeToken))
	routeLabel := "ech-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(routeSum[:20]))
	return utils.LeaseHostname(routeLabel, rootHostname)
}

// ECHHostnameHash returns the validation hash of a lease's public fallback
// hostname. The relay stores it instead of the plaintext hostname for
// ECH-routed leases and matches plaintext lookups against it.
func ECHHostnameHash(hostname string) string {
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("portal hostname hash v1\x00" + hostname))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
