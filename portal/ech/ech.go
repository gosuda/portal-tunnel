// Package ech owns Portal's Encrypted Client Hello semantics: how tenant ECH
// route hostnames, fallback hostname hashes, and key/config material are
// derived, represented, validated, and encoded for DNS publication.
//
// The SDK and the relay own when and why these operations happen (lease
// sessions, TLS listeners, DNS publication, lease lifecycle); this package
// owns what ECH means. It depends on neither runtime.
package ech

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/keyless"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Materials is the immutable ECH material for one lease endpoint, prepared
// once from the owning identity. RouteHostname is the opaque outer SNI route,
// HostnameHash validates the public fallback hostname, and Keys/ConfigList
// carry the HPKE key and ECHConfigList for TLS and DNS publication.
type Materials struct {
	RouteHostname string
	HostnameHash  string
	ConfigList    []byte
	Keys          []tls.EncryptedClientHelloKey
}

// Prepare derives the complete tenant ECH material set for a lease from the
// tunnel identity, its public fallback hostname, and the relay root hostname.
func Prepare(id types.Identity, publicHostname, rootHostname string) (Materials, error) {
	routeHostname, err := RouteHostname(id, publicHostname, rootHostname)
	if err != nil {
		return Materials{}, err
	}
	seed, err := identity.DeriveToken(id, "tenant-ech", publicHostname, routeHostname)
	if err != nil {
		return Materials{}, fmt.Errorf("derive tenant ech seed: %w", err)
	}
	keys, configList, err := keyless.EncryptedClientHelloMaterials(seed, routeHostname)
	if err != nil {
		return Materials{}, fmt.Errorf("prepare tenant ech materials: %w", err)
	}
	return Materials{
		RouteHostname: routeHostname,
		HostnameHash:  HostnameHash(publicHostname),
		ConfigList:    configList,
		Keys:          keys,
	}, nil
}

// RelayMaterials derives the ECH key/config material for the relay's own API
// listener from the relay identity and its persistent ECH seed.
func RelayMaterials(id types.Identity, seed, publicName string) ([]tls.EncryptedClientHelloKey, []byte, error) {
	echSeed, err := identity.DeriveToken(id, "relay-ech", seed, publicName)
	if err != nil {
		return nil, nil, fmt.Errorf("derive relay ech seed: %w", err)
	}
	return keyless.EncryptedClientHelloMaterials(echSeed, publicName)
}

// RouteHostname derives the opaque ECH route hostname for a tenant lease: an
// identity-derived token is compressed into one DNS label under the relay
// root hostname, hiding the tenant identity from the relay while routing
// ECH connections.
func RouteHostname(id types.Identity, publicHostname, rootHostname string) (string, error) {
	routeToken, err := identity.DeriveToken(id, "ech-route", publicHostname, rootHostname)
	if err != nil {
		return "", err
	}
	routeSum := sha256.Sum256([]byte(routeToken))
	routeLabel := "ech-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(routeSum[:20]))
	return utils.LeaseHostname(routeLabel, rootHostname)
}

// HostnameHash returns the validation hash of a lease's public fallback
// hostname. The relay stores it instead of the plaintext hostname for
// ECH-routed leases and matches plaintext lookups against it.
func HostnameHash(hostname string) string {
	hostname = utils.NormalizeHostname(hostname)
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("portal hostname hash v1\x00" + hostname))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NormalizeRegistration validates and normalizes the ECH fields of a lease
// registration. routeHostname is the raw requested route, publicHostname the
// plaintext fallback hostname derived by the caller (empty when not
// derivable), and rootHostname the relay root the route must live under. It
// returns the hostname hash and ECHConfigList ready for record storage.
func NormalizeRegistration(routeHostname, hostnameHash string, echConfigList []byte, publicHostname, rootHostname string) (string, []byte, error) {
	routeHostname = utils.NormalizeHostname(routeHostname)
	hostnameHash = strings.TrimSpace(hostnameHash)
	if hostnameHash != "" && routeHostname == "" {
		return "", nil, errors.New("hostname hash requires route hostname")
	}
	if len(echConfigList) > 0 && routeHostname == "" {
		return "", nil, errors.New("ech config list requires route hostname")
	}
	if routeHostname != "" {
		routeLabel, routeBase, ok := strings.Cut(routeHostname, ".")
		normalizedRouteLabel, labelErr := utils.NormalizeDNSLabel(routeLabel)
		if !ok || labelErr != nil || normalizedRouteLabel != routeLabel || routeBase != rootHostname {
			return "", nil, errors.New("route hostname must be a child of relay root hostname")
		}
		if publicHostname != "" {
			expectedHostnameHash := HostnameHash(publicHostname)
			if hostnameHash != "" && hostnameHash != expectedHostnameHash {
				return "", nil, errors.New("hostname hash does not match public hostname")
			}
			hostnameHash = expectedHostnameHash
		}
	}
	if len(echConfigList) > 0 {
		normalized, err := NormalizeConfigList(echConfigList)
		if err != nil {
			return "", nil, err
		}
		echConfigList = normalized
	}
	return hostnameHash, echConfigList, nil
}

// NormalizeConfigList validates and normalizes a wire ECHConfigList without
// registration context, for early challenge-time validation.
func NormalizeConfigList(raw []byte) ([]byte, error) {
	return keyless.NormalizeEncryptedClientHelloConfigList(raw)
}

// HTTPSRecordValue renders the SVCB service parameters of an HTTPS record
// publishing an ECHConfigList, with an explicit non-443 port when needed.
func HTTPSRecordValue(echConfigList []byte, port int) (string, error) {
	echConfigList, err := NormalizeConfigList(echConfigList)
	if err != nil {
		return "", err
	}
	svcParams := `ech="` + base64.StdEncoding.EncodeToString(echConfigList) + `"`
	if port > 0 && port != 443 {
		svcParams += " port=" + strconv.Itoa(port)
	}
	return svcParams, nil
}
