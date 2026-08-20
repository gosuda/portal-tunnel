package dnsrecord

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type HTTPSRecord struct {
	Priority  uint16
	Target    string
	SvcParams string
}

func (r HTTPSRecord) Normalized() (HTTPSRecord, error) {
	target := strings.TrimSpace(r.Target)
	if target == "" {
		target = "."
	} else if target != "." {
		target = strings.TrimSuffix(target, ".") + "."
	}
	priority := r.Priority
	if priority == 0 {
		priority = 1
	}
	svcParams := strings.TrimSpace(r.SvcParams)
	if svcParams == "" {
		return HTTPSRecord{}, errors.New("https record svc params are required")
	}
	return HTTPSRecord{Priority: priority, Target: target, SvcParams: svcParams}, nil
}

func (r HTTPSRecord) Content() (string, error) {
	normalized, err := r.Normalized()
	if err != nil {
		return "", err
	}
	return strconv.Itoa(int(normalized.Priority)) + " " + normalized.Target + " " + normalized.SvcParams, nil
}

// RelativeName converts a fully qualified record name into the form expected
// by DNS provider APIs while preserving provider-specific error messages.
func RelativeName(provider, fqdn, zone string) (string, error) {
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)
	if fqdn == "" {
		return "", errors.New("record name is required")
	}
	if zone == "" {
		return "", fmt.Errorf("%s zone is required", provider)
	}
	if fqdn == zone {
		return "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("hostname %q is outside %s zone %q", fqdn, provider, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

// NameMatches accepts the relative, apex, and fully qualified record-name
// forms returned by DNS provider APIs for the same record.
func NameMatches(recordName, expected, fqdn, zone string) bool {
	recordName = utils.NormalizeHostname(recordName)
	expected = strings.TrimSpace(strings.ToLower(expected))
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)

	if recordName == expected {
		return true
	}
	if expected == "@" && (recordName == "" || recordName == zone || recordName == fqdn) {
		return true
	}
	return recordName == fqdn
}

// TXTContent normalizes the quoted TXT values returned by DNS provider APIs.
func TXTContent(raw string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(raw))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(raw), "\"")
}
