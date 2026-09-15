package keyless

import (
	"errors"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
