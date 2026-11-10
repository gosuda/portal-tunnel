package dnsrecord

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRecordNameIsRequired = errors.New("record name is required")
	errBaseDomainIsRequired = errors.New("base domain is required")
)

func RecordName(raw string) (string, error) {
	name := utils.NormalizeHostname(raw)
	if name == "" {
		return "", errRecordNameIsRequired
	}
	return name, nil
}

func BaseDomain(raw string) (string, error) {
	name := utils.NormalizeBaseDomain(raw)
	if name == "" {
		return "", errBaseDomainIsRequired
	}
	return name, nil
}

func AddressRecordInputs(name, publicIP string) (recordName, recordType, canonicalIP string, err error) {
	recordName, err = RecordName(name)
	if err != nil {
		return "", "", "", err
	}
	recordType, canonicalIP, err = address(publicIP)
	if err != nil {
		return "", "", "", err
	}
	return recordName, recordType, canonicalIP, nil
}

func AddressRecordsInputs(baseDomain, publicIP string) (normalizedBaseDomain, recordType, canonicalIP string, err error) {
	normalizedBaseDomain, err = BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}
	recordType, canonicalIP, err = address(publicIP)
	if err != nil {
		return "", "", "", err
	}
	return normalizedBaseDomain, recordType, canonicalIP, nil
}

func address(raw string) (recordType, canonicalIP string, err error) {
	canonicalIP = utils.SanitizeReportedIP(raw)
	if canonicalIP == "" {
		return "", "", fmt.Errorf("invalid ip address: %q", raw)
	}
	recordType = "A"
	if strings.Contains(canonicalIP, ":") {
		recordType = "AAAA"
	}
	return recordType, canonicalIP, nil
}

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

func ApexWildcard(baseDomain string) []string {
	return []string{baseDomain, "*." + baseDomain}
}

func required(raw, label string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}

func RelativeName(provider, fqdn, zone string) (string, error) {
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)
	if fqdn == "" {
		return "", errRecordNameIsRequired
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

func TXTContent(raw string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(raw))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(raw), "\"")
}
