package pgns

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"

	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	// DefaultZone is the default global PGNS zone suffix.
	DefaultZone = "portal.gosuda.org"

	idTagDomain     = "portal-pgns-id-v1\x00"
	subkeySalt      = "portal-pgns-subkey-v1"
	recoveryDomain  = "portal-pgns-recovery-v1\x00"
	idTagByteLen    = 16
	idTagStringLen  = 26
	minAliasLen     = 4
	maxFQDNLen      = 253
	maxLabelLen     = 63
	subzoneIDLabel  = "id"
	subzoneAppLabel = "app"
)

var (
	// ErrInvalidZone marks a malformed or non-canonical PGNS zone name.
	ErrInvalidZone = errors.New("pgns: invalid zone")
	// ErrInvalidFQDN marks an out-of-scope, malformed, or reserved FQDN.
	ErrInvalidFQDN = errors.New("pgns: invalid fqdn")
	// ErrReservedLabel marks a hostname rejected by scoped label policy.
	ErrReservedLabel = errors.New("pgns: reserved label")
	// ErrKeyDerivationFailed marks impossible or invalid subkey derivation inputs.
	ErrKeyDerivationFailed = errors.New("pgns: subkey derivation failed")
)

var base32LowerNoPad = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var reservedAppLabels = map[string]struct{}{
	"ns": {}, "ns1": {}, "ns2": {}, "ns3": {}, "ns4": {}, "ns5": {}, "ns6": {}, "ns7": {}, "ns8": {},
	"pgns": {}, "witness": {}, "www": {}, "api": {}, "admin": {}, "mail": {}, "smtp": {}, "imap": {},
	"pop": {}, "wpad": {}, "autoconfig": {}, "autodiscover": {}, "metrics": {}, "status": {}, "health": {},
}

var reservedIDServiceLabels = map[string]struct{}{
	"wpad": {}, "autoconfig": {}, "autodiscover": {},
}

// FQDNClass identifies the PGNS subzone ownership class.
type FQDNClass uint8

const (
	ClassSelfCertifying FQDNClass = 1
	ClassFriendlyAlias  FQDNClass = 2
)

// ParsedFQDN describes a validated canonical PGNS hostname relative to a zone.
type ParsedFQDN struct {
	FQDN    string
	Zone    string
	Class   FQDNClass
	Service string
	IDTag   string
	Alias   string
}

// NormalizeZone canonicalizes a user-supplied PGNS zone string and validates it.
func NormalizeZone(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimSuffix(trimmed, ".")
	lower := strings.ToLower(trimmed)
	if err := ValidateZone(lower); err != nil {
		return "", err
	}
	return lower, nil
}

// ValidateZone checks that zone is a canonical lowercase ASCII LDH domain name
// with at least two labels and no trailing dot.
func ValidateZone(zone string) error {
	if err := validateCanonicalDomain(zone, 2, maxFQDNLen); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidZone, err)
	}
	return nil
}

// ParseScopedFQDN validates that fqdn is strictly canonical lowercase ASCII and
// belongs to either <service>.<id-tag>.id.<zone> or <alias>.app.<zone>.
func ParseScopedFQDN(fqdn, zone string) (ParsedFQDN, error) {
	if err := ValidateZone(zone); err != nil {
		return ParsedFQDN{}, err
	}
	if err := validateCanonicalDomain(fqdn, 3, maxFQDNLen); err != nil {
		return ParsedFQDN{}, fmt.Errorf("%w: %w", ErrInvalidFQDN, err)
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return ParsedFQDN{}, fmt.Errorf("%w: not under zone %s", ErrInvalidFQDN, zone)
	}
	rel := strings.TrimSuffix(fqdn, suffix)
	labels := strings.Split(rel, ".")
	switch {
	case len(labels) == 3 && labels[2] == subzoneIDLabel:
		return parseIDFQDN(fqdn, zone, labels[0], labels[1])
	case len(labels) == 2 && labels[1] == subzoneAppLabel:
		return parseAppFQDN(fqdn, zone, labels[0])
	default:
		return ParsedFQDN{}, fmt.Errorf("%w: unsupported label depth under %s", ErrInvalidFQDN, zone)
	}
}

func parseIDFQDN(fqdn, zone, service, idTag string) (ParsedFQDN, error) {
	if strings.HasPrefix(service, "_") {
		return ParsedFQDN{}, fmt.Errorf("%w: service label %q starts with underscore", ErrReservedLabel, service)
	}
	if _, reserved := reservedIDServiceLabels[service]; reserved {
		return ParsedFQDN{}, fmt.Errorf("%w: service label %q is reserved", ErrReservedLabel, service)
	}
	if !IsValidIDTag(idTag) {
		return ParsedFQDN{}, fmt.Errorf("%w: invalid id-tag %q", ErrInvalidFQDN, idTag)
	}
	return ParsedFQDN{
		FQDN:    fqdn,
		Zone:    zone,
		Class:   ClassSelfCertifying,
		Service: service,
		IDTag:   idTag,
	}, nil
}

func parseAppFQDN(fqdn, zone, alias string) (ParsedFQDN, error) {
	if len(alias) < minAliasLen {
		return ParsedFQDN{}, fmt.Errorf("%w: alias %q shorter than %d characters", ErrInvalidFQDN, alias, minAliasLen)
	}
	if strings.HasPrefix(alias, "_") {
		return ParsedFQDN{}, fmt.Errorf("%w: alias %q starts with underscore", ErrReservedLabel, alias)
	}
	if _, reserved := reservedAppLabels[alias]; reserved {
		return ParsedFQDN{}, fmt.Errorf("%w: alias label %q is reserved", ErrReservedLabel, alias)
	}
	return ParsedFQDN{
		FQDN:  fqdn,
		Zone:  zone,
		Class: ClassFriendlyAlias,
		Alias: alias,
	}, nil
}

// IsValidIDTag checks the canonical 26-char lowercase unpadded RFC 4648 base32
// encoding of a 16-byte digest, including zero trailing pad bits.
func IsValidIDTag(tag string) bool {
	if len(tag) != idTagStringLen {
		return false
	}
	for i := range len(tag) {
		c := tag[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	decoded, err := base32LowerNoPad.DecodeString(tag)
	if err != nil || len(decoded) != idTagByteLen {
		return false
	}
	return base32LowerNoPad.EncodeToString(decoded) == tag
}

// DeriveIDTag returns the 26-char self-certifying <id-tag> for a compressed
// 33-byte secp256k1 public key.
func DeriveIDTag(compressedPubKey [33]byte) (string, error) {
	if _, err := identity.ParseSecp256k1CompressedPubKey33(compressedPubKey); err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(idTagDomain))
	_, _ = h.Write(compressedPubKey[:])
	sum := h.Sum(nil)
	return base32LowerNoPad.EncodeToString(sum[:idTagByteLen]), nil
}

// RecoveryKeyHash returns SHA256("portal-pgns-recovery-v1\x00" || coldPubKey).
func RecoveryKeyHash(compressedColdPubKey [33]byte) ([32]byte, error) {
	if _, err := identity.ParseSecp256k1CompressedPubKey33(compressedColdPubKey); err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(recoveryDomain))
	_, _ = h.Write(compressedColdPubKey[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// DeriveIDSiteKey derives the non-circular per-site secp256k1 private key for
// <service>.<id-tag>.id.<zone> namespaces before computing <id-tag>.
func DeriveIDSiteKey(masterKey *secp256k1.PrivateKey, zone, siteKeyLabel string) (*secp256k1.PrivateKey, error) {
	if masterKey == nil || masterKey.Key.IsZero() {
		return nil, ErrKeyDerivationFailed
	}
	normZone, err := NormalizeZone(zone)
	if err != nil {
		return nil, err
	}
	label := strings.TrimSpace(siteKeyLabel)
	if label == "" {
		label = types.UnnamedServiceLabel
	}
	baseInfo := make([]byte, 0, len(subzoneIDLabel)+1+len(normZone)+1+len(label)+1)
	baseInfo = append(baseInfo, subzoneIDLabel...)
	baseInfo = append(baseInfo, 0)
	baseInfo = append(baseInfo, normZone...)
	baseInfo = append(baseInfo, 0)
	baseInfo = append(baseInfo, label...)
	return deriveSiteSubkey(masterKey, baseInfo)
}

// DeriveAppSiteKey derives the non-circular per-site secp256k1 private key for
// an <alias>.app.<zone> FQDN.
func DeriveAppSiteKey(masterKey *secp256k1.PrivateKey, fqdn string) (*secp256k1.PrivateKey, error) {
	if masterKey == nil || masterKey.Key.IsZero() {
		return nil, ErrKeyDerivationFailed
	}
	lowerFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if err := validateCanonicalDomain(lowerFQDN, 4, maxFQDNLen); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFQDN, err)
	}
	baseInfo := make([]byte, 0, len(subzoneAppLabel)+1+len(lowerFQDN)+1)
	baseInfo = append(baseInfo, subzoneAppLabel...)
	baseInfo = append(baseInfo, 0)
	baseInfo = append(baseInfo, lowerFQDN...)
	return deriveSiteSubkey(masterKey, baseInfo)
}

func deriveSiteSubkey(masterKey *secp256k1.PrivateKey, baseInfo []byte) (*secp256k1.PrivateKey, error) {
	ikm := masterKey.Serialize()
	salt := []byte(subkeySalt)
	info := make([]byte, len(baseInfo)+1)
	copy(info, baseInfo)

	var buf [32]byte
	for counter := range 256 {
		info[len(baseInfo)] = byte(counter)
		reader := hkdf.New(sha256.New, ikm, salt, info)
		if _, err := reader.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyDerivationFailed, err)
		}
		var tweak secp256k1.ModNScalar
		tweak.SetByteSlice(buf[:])
		if tweak.IsZero() {
			continue
		}
		var derived secp256k1.ModNScalar
		derived.Set(&masterKey.Key).Add(&tweak)
		if derived.IsZero() {
			continue
		}
		var scalarBytes [32]byte
		derived.PutBytes(&scalarBytes)
		return secp256k1.PrivKeyFromBytes(scalarBytes[:]), nil
	}
	return nil, ErrKeyDerivationFailed
}

func validateCanonicalDomain(domain string, minLabels, maxLen int) error {
	if len(domain) == 0 || len(domain) > maxLen {
		return fmt.Errorf("domain length %d out of range", len(domain))
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return errors.New("leading or trailing dot")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < minLabels {
		return fmt.Errorf("expected at least %d labels, got %d", minLabels, len(labels))
	}
	for _, label := range labels {
		if !isValidLowerLDHLabel(label) {
			return fmt.Errorf("invalid label %q", label)
		}
	}
	return nil
}

func isValidLowerLDHLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelLen {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		c := label[i]
		isLowerAlpha := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLowerAlpha && !isDigit && c != '-' {
			return false
		}
	}
	return true
}
