package keyless

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	echConfigVersion       = 0xfe0d
	echKEMX25519           = 0x0020
	echKDFHKDFSHA256       = 0x0001
	echAEADAES128GCM       = 0x0001
	echMaximumNameLength   = 255
	echMaxConfigListLength = 4096
	echX25519PrivateLength = 32
	echHKDFInfoPrefix      = "portal relay ech v1:"
)

// MinTLSVersion returns the minimum TLS version required when ECH is enabled.
func MinTLSVersion(echEnabled bool) uint16 {
	if echEnabled {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func EncryptedClientHelloMaterials(seed, publicName string) ([]tls.EncryptedClientHelloKey, []byte, error) {
	publicName = utils.NormalizeHostname(publicName)
	if publicName == "" {
		return nil, nil, errors.New("ech public name is required")
	}
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return nil, nil, errors.New("ech seed is required")
	}

	if len(publicName) > echMaximumNameLength {
		return nil, nil, errors.New("ech public name is too long")
	}

	privateKey, err := hkdf.Key(sha256.New, []byte(seed), nil, echHKDFInfoPrefix+publicName, echX25519PrivateLength)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ech private key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ech private key: %w", err)
	}
	publicKey := key.PublicKey().Bytes()
	configID := sha256.Sum256(bytes.Join([][]byte{
		[]byte("portal relay ech config id v1"),
		[]byte(publicName),
		publicKey,
	}, []byte{0}))[0]

	writeUint16 := func(buf *bytes.Buffer, value uint16) {
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], value)
		buf.Write(out[:])
	}
	writeUint16LengthPrefixed := func(buf *bytes.Buffer, data []byte) {
		writeUint16(buf, uint16(len(data)))
		buf.Write(data)
	}

	var body bytes.Buffer
	body.WriteByte(configID)
	writeUint16(&body, echKEMX25519)
	writeUint16LengthPrefixed(&body, publicKey)

	var cipherSuites bytes.Buffer
	writeUint16(&cipherSuites, echKDFHKDFSHA256)
	writeUint16(&cipherSuites, echAEADAES128GCM)
	writeUint16LengthPrefixed(&body, cipherSuites.Bytes())

	body.WriteByte(echMaximumNameLength)
	body.WriteByte(byte(len(publicName)))
	body.WriteString(publicName)
	writeUint16(&body, 0)

	var out bytes.Buffer
	writeUint16(&out, echConfigVersion)
	writeUint16LengthPrefixed(&out, body.Bytes())

	keys := []tls.EncryptedClientHelloKey{{
		Config:      out.Bytes(),
		PrivateKey:  privateKey,
		SendAsRetry: true,
	}}

	var configList bytes.Buffer
	var configListLength [2]byte
	binary.BigEndian.PutUint16(configListLength[:], uint16(len(keys[0].Config)))
	configList.Write(configListLength[:])
	configList.Write(keys[0].Config)

	return keys, configList.Bytes(), nil
}

func NormalizeEncryptedClientHelloConfigList(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("ech config list is required")
	}
	if len(raw) > echMaxConfigListLength {
		return nil, errors.New("ech config list is too large")
	}
	if len(raw) < 2 {
		return nil, errors.New("ech config list is invalid")
	}
	listLength := int(binary.BigEndian.Uint16(raw[:2]))
	if listLength != len(raw)-2 {
		return nil, errors.New("ech config list length prefix is invalid")
	}
	return bytes.Clone(raw), nil
}

// HTTPSRecordValue renders the SVCB service parameters of an HTTPS record
// publishing an ECHConfigList, with an explicit non-443 port when needed.
// The port must be zero or a valid TCP port number.
func HTTPSRecordValue(echConfigList []byte, port int) (string, error) {
	if port < 0 || port > 65535 {
		return "", errors.New("https record port must be between 0 and 65535")
	}
	echConfigList, err := NormalizeEncryptedClientHelloConfigList(echConfigList)
	if err != nil {
		return "", err
	}
	svcParams := `ech="` + base64.StdEncoding.EncodeToString(echConfigList) + `"`
	if port > 0 && port != 443 {
		svcParams += " port=" + strconv.Itoa(port)
	}
	return svcParams, nil
}

// NormalizeECHRegistration validates and normalizes the ECH fields of a lease
// registration. routeHostname is the raw requested route, publicHostname the
// plaintext fallback hostname derived by the caller (empty when not
// derivable), and rootHostname the relay root the route must live under. It
// returns the hostname hash and ECHConfigList ready for record storage.
func NormalizeECHRegistration(routeHostname, hostnameHash string, echConfigList []byte, publicHostname, rootHostname string) (string, []byte, error) {
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
			expectedHostnameHash := ECHHostnameHash(publicHostname)
			if hostnameHash != "" && hostnameHash != expectedHostnameHash {
				return "", nil, errors.New("hostname hash does not match public hostname")
			}
			hostnameHash = expectedHostnameHash
		}
	}
	if len(echConfigList) > 0 {
		normalized, err := NormalizeEncryptedClientHelloConfigList(echConfigList)
		if err != nil {
			return "", nil, err
		}
		echConfigList = normalized
	}
	return hostnameHash, echConfigList, nil
}

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
