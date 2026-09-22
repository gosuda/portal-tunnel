package dnsrecord

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

// RecordName validates a fully qualified record name and returns it
// normalized.
func RecordName(raw string) (string, error) {
	name := utils.NormalizeHostname(raw)
	if name == "" {
		return "", errors.New("record name is required")
	}
	return name, nil
}

// BaseDomain validates a zone base domain and returns it normalized.
func BaseDomain(raw string) (string, error) {
	name := utils.NormalizeBaseDomain(raw)
	if name == "" {
		return "", errors.New("base domain is required")
	}
	return name, nil
}

// ARecordInputs validates an A-record upsert's record name and public IPv4
// address, returning the normalized record name.
func ARecordInputs(name, publicIPv4 string) (string, error) {
	name, err := RecordName(name)
	if err != nil {
		return "", err
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return "", err
	}
	return name, nil
}

// ARecordsInputs validates an apex and wildcard A-record upsert's base domain
// and public IPv4 address, returning the normalized base domain.
func ARecordsInputs(baseDomain, publicIPv4 string) (string, error) {
	baseDomain, err := BaseDomain(baseDomain)
	if err != nil {
		return "", err
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return "", err
	}
	return baseDomain, nil
}

// TXTInputs validates a TXT upsert's record name and value, returning both
// normalized.
func TXTInputs(name, value string) (string, string, error) {
	name, err := RecordName(name)
	if err != nil {
		return "", "", err
	}
	value, err = required(value, "txt record value")
	if err != nil {
		return "", "", err
	}
	return name, value, nil
}

// TXTPrefixInputs validates a TXT deletion's record name and match prefix,
// returning both normalized.
func TXTPrefixInputs(name, matchPrefix string) (string, string, error) {
	name, err := RecordName(name)
	if err != nil {
		return "", "", err
	}
	matchPrefix, err = required(matchPrefix, "txt record match prefix")
	if err != nil {
		return "", "", err
	}
	return name, matchPrefix, nil
}

// ApexWildcard lists the apex and wildcard record names published for a base
// domain.
func ApexWildcard(baseDomain string) []string {
	return []string{baseDomain, "*." + baseDomain}
}

// required trims raw and reports an empty input as "<label> is required".
func required(raw, label string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
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
	apexRecord := recordName == "" || recordName == zone || recordName == fqdn
	if expected == "@" && apexRecord {
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
