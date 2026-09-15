package keyless

import (
	"encoding/base64"
	"errors"
	"strconv"
)

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
