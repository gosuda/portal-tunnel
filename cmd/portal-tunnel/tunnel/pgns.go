package tunnel

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/pgns"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	pgnsCertFileName         = "cert.pem"
	pgnsKeyFileName          = "key.pem"
	pgnsACMEAccountKeyFile   = "acme-account.key"
	pgnsACMERegistrationFile = "acme-registration.json"

	pgnsLeafTTL             = uint64(24 * 3600)
	pgnsProbeBaseInterval   = 5 * time.Second
	pgnsProbeJitterMax      = 2 * time.Second
	pgnsProbeTimeout        = 4 * time.Second
	pgnsFailbackCooldown    = 5 * time.Minute
	pgnsFailbackJitterMax   = 30 * time.Second
	pgnsFailThreshold       = 2
	pgnsResolveMaxBytes     = 256 << 10
	pgnsSubmitRetryWait     = 200 * time.Millisecond
	pgnsEpochConfirmTimeout = 20 * time.Second
	pgnsACMECheckInterval   = time.Hour
	pgnsACMERenewBefore     = 30 * 24 * time.Hour
	pgnsBootstrapCertLife   = 365 * 24 * time.Hour
)

var (
	errPGNSWithRawTransport      = errors.New("PGNS cannot be combined with raw TCP or UDP")
	errPGNSWithExternalTLS       = errors.New("PGNS cannot be combined with --tls-auto, --tls-cert, or --tls-key")
	errPGNSZoneRequired          = errors.New("pgns_zone is required when PGNS options are set")
	errPGNSStateDirRequired      = errors.New("pgns_state_dir is required when no file-backed identity is configured")
	errPGNSSequencerRequired     = errors.New("at least one pgns_sequencer URL is required")
	errPGNSWitnessesRequired     = errors.New("at least one pgns_witness is required")
	errPGNSRecoveryIDForbidden   = errors.New("pgns_recovery_pubkey is supported only with --pgns-alias")
	errPGNSACMEEABUnpaired       = errors.New("pgns_acme_eab_kid and pgns_acme_eab_hmac must be configured together")
	errPGNSACMEEABNeedsDirectory = errors.New("pgns_acme_eab credentials require pgns_acme_directory")
	errPGNSPersistNeedsIssuer    = errors.New("pgns_persist01 requires pgns_acme_caa_issuer")
	errPGNSNoDialableRelays      = errors.New("PGNS resolved zero public relay endpoints")
	errPGNSHttpURLRequired       = errors.New("must be an http:// or https:// URL")
	errPGNSCompressedPubKeyHex   = errors.New("expected 33-byte compressed hex secp256k1 public key")
	errPGNSEndpointPairCount     = errors.New("expected 1 or 2 comma-separated addresses")
	errPGNSEndpointPortZero      = errors.New("endpoint port must be >= 1")
	errPGNSEndpointPortMismatch  = errors.New("mismatched ports between ipv4 and ipv6")
	errPGNSEndpointDupIPv4       = errors.New("duplicate ipv4 address")
	errPGNSEndpointDupIPv6       = errors.New("duplicate ipv6 address")
	errPGNSMasterKeyInvalid      = errors.New("master identity has invalid secp256k1 private key")
	errPGNSACMENoInitialLeaf     = errors.New("cannot stage ACME challenge before initial leaf exists")
)

type pgnsRelayEndpoint struct {
	url string
	ep  pgns.Endpoint
}

type pgnsEndpointOverride struct {
	ipv4 [4]byte
	ipv6 [16]byte
	port uint16
}

func validatePGNS(spec Spec) error {
	if spec.PGNS == nil {
		return nil
	}
	cfg := spec.PGNS
	if strings.TrimSpace(cfg.Zone) == "" {
		return errPGNSZoneRequired
	}
	normZone, err := pgns.NormalizeZone(cfg.Zone)
	if err != nil {
		return fmt.Errorf("invalid pgns_zone: %w", err)
	}
	if spec.Transport.TCP || spec.Transport.UDP != nil {
		return errPGNSWithRawTransport
	}
	if spec.TLSAuto || spec.TLSCert != "" || spec.TLSKey != "" {
		return errPGNSWithExternalTLS
	}
	if spec.HTTP != nil && spec.HTTP.Cache != nil {
		return errPGNSWithRelayCache
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return errPGNSStateDirRequired
	}
	if err := validatePGNSQuorum(cfg); err != nil {
		return err
	}
	if err := validatePGNSNamespace(cfg, spec.Identity.Name, normZone); err != nil {
		return err
	}
	if err := validatePGNSACME(cfg); err != nil {
		return err
	}
	_, err = parsePGNSEndpointOverrides(cfg.RelayEndpoints)
	return err
}

func validatePGNSQuorum(cfg *PGNSConfig) error {
	if len(cfg.Sequencers) == 0 {
		return errPGNSSequencerRequired
	}
	for _, rawURL := range cfg.Sequencers {
		if _, err := normalizeHTTPBaseURL(rawURL); err != nil {
			return fmt.Errorf("invalid pgns_sequencer %q: %w", rawURL, err)
		}
	}
	if len(cfg.Witnesses) == 0 {
		return errPGNSWitnessesRequired
	}
	ws, err := pgns.ParseWitnessSet(cfg.Witnesses, cfg.WitnessThreshold)
	if err != nil || ws.Threshold <= 0 || len(ws.Witnesses) == 0 {
		return fmt.Errorf("invalid pgns witnesses: %w", err)
	}
	return nil
}

func validatePGNSNamespace(cfg *PGNSConfig, rawName, normZone string) error {
	alias := strings.ToLower(strings.TrimSpace(cfg.Alias))
	if alias != "" {
		if _, err := pgns.ParseScopedFQDN(alias+".app."+normZone, normZone); err != nil {
			return fmt.Errorf("invalid pgns_alias %q: %w", cfg.Alias, err)
		}
		if cfg.RecoveryPubKey != "" {
			if _, err := parseCompressedPubKeyHex(cfg.RecoveryPubKey); err != nil {
				return fmt.Errorf("invalid pgns_recovery_pubkey: %w", err)
			}
		}
		return nil
	}
	if cfg.RecoveryPubKey != "" {
		return errPGNSRecoveryIDForbidden
	}
	serviceLabel := cmp.Or(strings.ToLower(strings.TrimSpace(rawName)), types.UnnamedServiceLabel)
	const dummyIDTag = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := pgns.ParseScopedFQDN(serviceLabel+"."+dummyIDTag+".id."+normZone, normZone); err != nil {
		return fmt.Errorf("invalid PGNS service name %q: %w", serviceLabel, err)
	}
	return nil
}

func validatePGNSACME(cfg *PGNSConfig) error {
	hasKID := cfg.ACMEEABKID != ""
	hasHMAC := cfg.ACMEEABHMAC != ""
	if hasKID != hasHMAC {
		return errPGNSACMEEABUnpaired
	}
	if hasKID && cfg.ACMEDirectory == "" {
		return errPGNSACMEEABNeedsDirectory
	}
	if cfg.ACMEDirectory != "" {
		parsed, err := url.Parse(cfg.ACMEDirectory)
		if err != nil || parsed.Host == "" || parsed.Scheme != "https" || parsed.User != nil {
			return fmt.Errorf("invalid pgns_acme_directory %q: must be an https:// URL", cfg.ACMEDirectory)
		}
	}
	if cfg.Persist01 && cfg.ACMECAIssuer == "" {
		return errPGNSPersistNeedsIssuer
	}
	return nil
}

func normalizeHTTPBaseURL(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(trimmed)
	validScheme := parsed != nil && (parsed.Scheme == "http" || parsed.Scheme == "https")
	if err != nil || parsed.Host == "" || !validScheme {
		return "", errPGNSHttpURLRequired
	}
	return trimmed, nil
}

func parseCompressedPubKeyHex(raw string) ([33]byte, error) {
	var out [33]byte
	cleaned := strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	decoded, err := hex.DecodeString(cleaned)
	if err != nil || len(decoded) != 33 {
		return out, errPGNSCompressedPubKeyHex
	}
	copy(out[:], decoded)
	if _, err := identity.ParseSecp256k1CompressedPubKey33(out); err != nil {
		return [33]byte{}, err
	}
	return out, nil
}

func parsePGNSEndpointOverrides(entries []string) (map[string]pgnsEndpointOverride, error) {
	out := make(map[string]pgnsEndpointOverride, len(entries))
	for _, entry := range entries {
		lhs, rhs, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || strings.TrimSpace(lhs) == "" || strings.TrimSpace(rhs) == "" {
			return nil, fmt.Errorf("invalid pgns endpoint %q (expected <relay-url>=<ip>[:port][,<ip6>])", entry)
		}
		relayURL, err := types.NormalizeRelayURL(lhs)
		if err != nil {
			return nil, fmt.Errorf("invalid pgns endpoint relay %q: %w", lhs, err)
		}
		ov, err := parseEndpointAddressPair(rhs)
		if err != nil {
			return nil, fmt.Errorf("invalid pgns endpoint target %q: %w", rhs, err)
		}
		out[relayURL] = ov
	}
	return out, nil
}

func parseEndpointAddressPair(raw string) (pgnsEndpointOverride, error) {
	var ov pgnsEndpointOverride
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > 2 {
		return ov, errPGNSEndpointPairCount
	}
	for _, part := range parts {
		addr, port, err := parsePublicAddrPort(strings.TrimSpace(part), 443)
		if err != nil {
			return pgnsEndpointOverride{}, err
		}
		if port == 0 {
			return pgnsEndpointOverride{}, errPGNSEndpointPortZero
		}
		if ov.port == 0 {
			ov.port = port
		} else if ov.port != port {
			return pgnsEndpointOverride{}, errPGNSEndpointPortMismatch
		}
		if addr.Is4() {
			if ov.ipv4 != ([4]byte{}) {
				return pgnsEndpointOverride{}, errPGNSEndpointDupIPv4
			}
			ov.ipv4 = addr.As4()
		} else {
			if ov.ipv6 != ([16]byte{}) {
				return pgnsEndpointOverride{}, errPGNSEndpointDupIPv6
			}
			ov.ipv6 = addr.As16()
		}
	}
	return ov, nil
}

func parsePublicAddrPort(raw string, defaultPort uint16) (netip.Addr, uint16, error) {
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		addr := ap.Addr().Unmap()
		if !utils.IsPublicIP(addr) {
			return netip.Addr{}, 0, fmt.Errorf("non-public ip %s", addr)
		}
		return addr, ap.Port(), nil
	}
	addr, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr = addr.Unmap()
	if !utils.IsPublicIP(addr) {
		return netip.Addr{}, 0, fmt.Errorf("non-public ip %s", addr)
	}
	return addr, defaultPort, nil
}

type pgnsController struct {
	zone       string
	fqdn       string
	stateDir   string
	certFile   string
	keyFile    string
	witnesses  pgns.WitnessSet
	sequencers []string
	httpClient *http.Client

	sitePriv     *secp256k1.PrivateKey
	sitePub33    [33]byte
	recoveryHash [32]byte

	acmeDir     string
	acmeEmail   string
	acmeIssuer  string
	acmeEABKID  string
	acmeEABHMAC string
	persist01   bool

	nowFn    func() time.Time
	probeFn  func(context.Context, string) error
	exposure *sdk.Exposure

	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu               sync.Mutex
	relays           []pgnsRelayEndpoint
	preferredPrimary string
	currentPrimary   string
	failCounts       map[string]int
	lastFailoverAt   time.Time
	failbackCooldown time.Duration
	spkiSHA256       [32]byte
	nextSPKI         [32]byte
	acmeDigest       [32]byte
	acmeAccountURI   string
	currentLeaf      pgns.PortalLeafRecord
	hasLeaf          bool
	lastProof        *types.PGNSRegistrationProof
}

func preparePGNSRuntime(ctx context.Context, spec Spec, masterIdentity types.Identity, explicitRelayURLs []string) (*pgnsController, types.Identity, error) {
	cfg := spec.PGNS
	zone, err := pgns.NormalizeZone(cfg.Zone)
	if err != nil {
		return nil, types.Identity{}, err
	}
	ws, err := pgns.ParseWitnessSet(cfg.Witnesses, cfg.WitnessThreshold)
	if err != nil {
		return nil, types.Identity{}, err
	}
	sitePriv, fqdn, serviceName, err := derivePGNSSiteIdentity(masterIdentity.PrivateKey, zone, spec.Identity.Name, cfg.Alias, cfg.SiteLabel)
	if err != nil {
		return nil, types.Identity{}, err
	}
	siteIdentity, err := buildSiteIdentity(sitePriv, serviceName)
	if err != nil {
		return nil, types.Identity{}, err
	}
	recoveryHash, err := parseOptionalRecoveryHash(cfg.RecoveryPubKey)
	if err != nil {
		return nil, types.Identity{}, err
	}
	relays, err := resolvePGNSRelayEndpoints(ctx, spec.Relays, explicitRelayURLs, cfg.RelayEndpoints)
	if err != nil {
		return nil, types.Identity{}, err
	}
	certFile, keyFile, spki, err := ensureInitialPGNSCert(cfg.StateDir, fqdn)
	if err != nil {
		return nil, types.Identity{}, err
	}
	sequencers := make([]string, 0, len(cfg.Sequencers))
	for _, rawSeq := range cfg.Sequencers {
		normSeq, seqErr := normalizeHTTPBaseURL(rawSeq)
		if seqErr != nil {
			return nil, types.Identity{}, seqErr
		}
		sequencers = append(sequencers, normSeq)
	}
	ctrl := &pgnsController{
		zone:             zone,
		fqdn:             fqdn,
		stateDir:         cfg.StateDir,
		certFile:         certFile,
		keyFile:          keyFile,
		witnesses:        ws,
		sequencers:       sequencers,
		httpClient:       utils.NewHTTPClient(utils.WithHTTPTimeout(10 * time.Second)),
		sitePriv:         sitePriv,
		sitePub33:        compressedPub33(sitePriv),
		recoveryHash:     recoveryHash,
		acmeDir:          cfg.ACMEDirectory,
		acmeEmail:        resolveACMEEmail(cfg.ACMEEmail, fqdn),
		acmeIssuer:       resolveACMEIssuer(cfg.ACMECAIssuer, cfg.ACMEDirectory),
		acmeEABKID:       cfg.ACMEEABKID,
		acmeEABHMAC:      cfg.ACMEEABHMAC,
		persist01:        cfg.Persist01,
		nowFn:            time.Now,
		relays:           relays,
		preferredPrimary: relays[0].url,
		currentPrimary:   relays[0].url,
		failCounts:       make(map[string]int, len(relays)),
		failbackCooldown: pgnsFailbackCooldown,
		spkiSHA256:       spki,
	}
	ctrl.loadExistingACMERegistration()
	if err := ctrl.ensureLeafRegistered(ctx); err != nil {
		return nil, types.Identity{}, err
	}
	return ctrl, siteIdentity, nil
}

func derivePGNSSiteIdentity(masterHex, zone, serviceName, alias, siteLabel string) (*secp256k1.PrivateKey, string, string, error) {
	rawKey, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(masterHex), "0x"))
	if err != nil || len(rawKey) != 32 {
		return nil, "", "", errPGNSMasterKeyInvalid
	}
	masterPriv := secp256k1.PrivKeyFromBytes(rawKey)
	if alias != "" {
		normAlias := strings.ToLower(strings.TrimSpace(alias))
		fqdn := normAlias + ".app." + zone
		if _, err := pgns.ParseScopedFQDN(fqdn, zone); err != nil {
			return nil, "", "", err
		}
		sitePriv, err := pgns.DeriveAppSiteKey(masterPriv, fqdn)
		return sitePriv, fqdn, normAlias, err
	}
	svc := cmp.Or(strings.ToLower(strings.TrimSpace(serviceName)), types.UnnamedServiceLabel)
	sitePriv, err := pgns.DeriveIDSiteKey(masterPriv, zone, siteLabel)
	if err != nil {
		return nil, "", "", err
	}
	idTag, err := pgns.DeriveIDTag(compressedPub33(sitePriv))
	if err != nil {
		return nil, "", "", err
	}
	fqdn := svc + "." + idTag + ".id." + zone
	if _, err := pgns.ParseScopedFQDN(fqdn, zone); err != nil {
		return nil, "", "", err
	}
	return sitePriv, fqdn, svc, nil
}

func compressedPub33(priv *secp256k1.PrivateKey) [33]byte {
	var out [33]byte
	copy(out[:], priv.PubKey().SerializeCompressed())
	return out
}

func buildSiteIdentity(sitePriv *secp256k1.PrivateKey, serviceName string) (types.Identity, error) {
	payload, err := identity.Marshal(types.Identity{
		Name:       serviceName,
		PrivateKey: hex.EncodeToString(sitePriv.Serialize()),
	})
	if err != nil {
		return types.Identity{}, err
	}
	return identity.Parse(payload)
}

func parseOptionalRecoveryHash(raw string) ([32]byte, error) {
	if raw == "" {
		return [32]byte{}, nil
	}
	pub33, err := parseCompressedPubKeyHex(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return pgns.RecoveryKeyHash(pub33)
}

func resolvePGNSRelayEndpoints(ctx context.Context, relaySpec RelaySpec, explicitURLs, rawOverrides []string) ([]pgnsRelayEndpoint, error) {
	overrides, err := parsePGNSEndpointOverrides(rawOverrides)
	if err != nil {
		return nil, err
	}
	urls := explicitURLs
	if len(urls) == 0 {
		urls, err = discovery.ResolveRelayURLs(nil, relaySpec.Discovery)
		if err != nil {
			return nil, err
		}
	}
	out := make([]pgnsRelayEndpoint, 0, min(len(urls), pgns.MaxEndpoints))
	for _, rawURL := range urls {
		normURL, err := types.NormalizeRelayURL(rawURL)
		if err != nil {
			return nil, err
		}
		ep, ok, err := buildRelayEndpoint(ctx, normURL, overrides)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, pgnsRelayEndpoint{url: normURL, ep: ep})
		if len(out) >= pgns.MaxEndpoints {
			break
		}
	}
	if len(out) == 0 {
		return nil, errPGNSNoDialableRelays
	}
	if out[0].ep.Port != 443 {
		return nil, fmt.Errorf("primary relay %s must expose port 443 for PGNS browsers (got %d)", out[0].url, out[0].ep.Port)
	}
	return out, nil
}

func buildRelayEndpoint(ctx context.Context, normURL string, overrides map[string]pgnsEndpointOverride) (pgns.Endpoint, bool, error) {
	idDigest := sha256.Sum256([]byte(normURL))
	ep := pgns.Endpoint{}
	copy(ep.RelayID[:], idDigest[:20])
	if ov, found := overrides[normURL]; found {
		ep.IPv4 = ov.ipv4
		ep.IPv6 = ov.ipv6
		ep.Port = ov.port
		return ep, true, nil
	}
	parsed, err := url.Parse(normURL)
	if err != nil {
		return ep, false, err
	}
	host := parsed.Hostname()
	if addr, port, parseErr := parsePublicAddrPort(host, 443); parseErr == nil {
		assignAddr(&ep, addr)
		ep.Port = port
		return ep, true, nil
	}
	addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for _, raw := range addrs {
		addr := raw.Unmap()
		if !utils.IsPublicIP(addr) {
			continue
		}
		assignAddr(&ep, addr)
	}
	if ep.IPv4 == ([4]byte{}) && ep.IPv6 == ([16]byte{}) {
		return ep, false, nil
	}
	ep.Port = 443
	return ep, true, nil
}

func assignAddr(ep *pgns.Endpoint, addr netip.Addr) {
	if addr.Is4() && ep.IPv4 == ([4]byte{}) {
		ep.IPv4 = addr.As4()
	} else if addr.Is6() && ep.IPv6 == ([16]byte{}) {
		ep.IPv6 = addr.As16()
	}
}

func ensureInitialPGNSCert(stateDir, fqdn string) (certFile, keyFile string, spki [32]byte, err error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", "", [32]byte{}, fmt.Errorf("create pgns state dir: %w", err)
	}
	certFile = filepath.Join(stateDir, pgnsCertFileName)
	keyFile = filepath.Join(stateDir, pgnsKeyFileName)
	if spki, ok := reusableSingleSANCert(certFile, keyFile, fqdn, time.Now().UTC()); ok {
		return certFile, keyFile, spki, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", [32]byte{}, fmt.Errorf("generate pgns tls key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", [32]byte{}, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fqdn},
		DNSNames:              []string{fqdn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(pgnsBootstrapCertLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", [32]byte{}, fmt.Errorf("create pgns self-signed cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", [32]byte{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := utils.WriteFileAtomic(certFile, certPEM, 0o644); err != nil {
		return "", "", [32]byte{}, err
	}
	if err := utils.WriteFileAtomic(keyFile, keyPEM, 0o600); err != nil {
		return "", "", [32]byte{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", [32]byte{}, err
	}
	return certFile, keyFile, sha256.Sum256(leaf.RawSubjectPublicKeyInfo), nil
}

func reusableSingleSANCert(certFile, keyFile, fqdn string, now time.Time) ([32]byte, bool) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return [32]byte{}, false
	}
	if _, err := os.ReadFile(keyFile); err != nil {
		return [32]byte{}, false
	}
	cert, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return [32]byte{}, false
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != fqdn {
		return [32]byte{}, false
	}
	if !now.Before(cert.NotAfter.Add(-time.Hour)) || now.Before(cert.NotBefore) {
		return [32]byte{}, false
	}
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo), true
}

func (c *pgnsController) loadExistingACMERegistration() {
	if c.acmeDir == "" {
		return
	}
	var reg registration.Resource
	regPath := filepath.Join(c.stateDir, pgnsACMERegistrationFile)
	ok, err := utils.ReadJSONFileIfExists(regPath, &reg)
	if err == nil && ok && strings.HasPrefix(reg.URI, "https://") {
		c.acmeAccountURI = reg.URI
	}
}

func (c *pgnsController) proof(ctx context.Context) (*types.PGNSRegistrationProof, error) {
	proof, _, _, err := c.fetchVerifiedResolve(ctx)
	if err == nil {
		return proof, nil
	}
	c.mu.Lock()
	cached := c.lastProof
	c.mu.Unlock()
	if cached != nil {
		nowUnix := uint64(max(0, c.nowFn().UTC().Unix()))
		if _, _, verErr := pgns.VerifyRegistrationProof(c.zone, c.witnesses, cached.Leaf, cached.InclusionProof, cached.Checkpoint, nowUnix); verErr == nil {
			return cached, nil
		}
	}
	return nil, err
}

func (c *pgnsController) fetchVerifiedResolve(ctx context.Context) (*types.PGNSRegistrationProof, pgns.PortalLeafRecord, pgns.Checkpoint, error) {
	nowUnix := uint64(max(0, c.nowFn().UTC().Unix()))
	var lastErr error
	for _, baseURL := range c.sequencers {
		raw, err := c.httpGetBytes(ctx, baseURL+types.PathV1ResolvePrefix+url.PathEscape(c.fqdn), pgnsResolveMaxBytes)
		if err != nil {
			lastErr = err
			continue
		}
		leaf, cp, err := pgns.VerifyResolveBundle(raw, c.fqdn, c.zone, c.witnesses, nowUnix)
		if err != nil {
			lastErr = err
			continue
		}
		bundle, err := pgns.UnmarshalResolveBundle(raw)
		if err != nil {
			lastErr = err
			continue
		}
		proof := &types.PGNSRegistrationProof{
			Zone:           c.zone,
			Leaf:           bundle.Leaf,
			InclusionProof: bundle.InclusionProof,
			Checkpoint:     bundle.SignedCheckpoint,
		}
		c.mu.Lock()
		c.currentLeaf = leaf
		c.hasLeaf = true
		c.lastProof = proof
		c.mu.Unlock()
		return proof, leaf, cp, nil
	}
	if lastErr == nil {
		lastErr = errPGNSSequencerRequired
	}
	return nil, pgns.PortalLeafRecord{}, pgns.Checkpoint{}, lastErr
}

func (c *pgnsController) httpGetBytes(ctx context.Context, targetURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response from %s exceeds limit", targetURL)
	}
	return data, nil
}

func (c *pgnsController) ensureLeafRegistered(ctx context.Context) error {
	nowUnix := uint64(max(0, c.nowFn().UTC().Unix()))
	_, existing, _, err := c.fetchVerifiedResolve(ctx)
	txType := pgns.TxTypeCreate
	seq := uint64(1)
	if err == nil {
		pastGrace := nowUnix > existing.ExpiresAt && nowUnix-existing.ExpiresAt > pgns.ReclaimGrace
		if !pastGrace {
			if existing.OwnerPubKey != c.sitePub33 {
				return fmt.Errorf("pgns leaf %s owned by another key until expiry grace ends", c.fqdn)
			}
			txType = pgns.TxTypeUpdate
			seq = existing.Seq + 1
		} else {
			txType = pgns.TxTypeReclaim
			seq = existing.Seq + 1
		}
	}
	return c.publishAndConfirm(ctx, txType, seq, true)
}

func (c *pgnsController) publishAndConfirm(ctx context.Context, txType uint8, seq uint64, waitConfirm bool) error {
	if txType == pgns.TxTypeUpdate {
		if _, latest, _, err := c.fetchVerifiedResolve(ctx); err == nil && latest.Seq+1 > seq {
			seq = latest.Seq + 1
		}
	}
	c.mu.Lock()
	leaf := c.buildDesiredLeafLocked(seq)
	c.mu.Unlock()

	rawTx, err := c.buildSignedTx(txType, leaf)
	if err != nil {
		return err
	}
	if err := c.submitTx(ctx, rawTx); err != nil {
		return err
	}
	if !waitConfirm {
		return nil
	}
	return c.waitForSeqConfirmed(ctx, leaf.Seq)
}

func (c *pgnsController) buildDesiredLeafLocked(seq uint64) pgns.PortalLeafRecord {
	nowUnix := uint64(max(0, c.nowFn().UTC().Unix()))
	flags := pgns.FlagHTTP2
	issuer := ""
	accountURI := ""
	var digest [32]byte
	if c.acmeAccountURI != "" && c.acmeIssuer != "" {
		issuer = c.acmeIssuer
		accountURI = c.acmeAccountURI
		digest = c.acmeDigest
		if c.persist01 {
			flags |= pgns.FlagPersist01Enabled
		}
	}
	return pgns.PortalLeafRecord{
		Version:           pgns.LeafVersion,
		Flags:             flags,
		FQDN:              c.fqdn,
		Seq:               seq,
		IssuedAt:          nowUnix,
		ExpiresAt:         nowUnix + pgnsLeafTTL,
		OwnerPubKey:       c.sitePub33,
		RecoveryKeyHash:   c.recoveryHash,
		TLSSPKISHA256:     c.spkiSHA256,
		NextTLSSPKISHA256: c.nextSPKI,
		ACMECAIssuer:      issuer,
		ACMEAccountURI:    accountURI,
		ACMEDNS01Digest:   digest,
		Endpoints:         c.orderedEndpointsLocked(),
	}
}

func (c *pgnsController) orderedEndpointsLocked() []pgns.Endpoint {
	ordered := make([]pgnsRelayEndpoint, 0, len(c.relays))
	for _, r := range c.relays {
		if r.url == c.currentPrimary {
			ordered = append(ordered, r)
		}
	}
	for _, r := range c.relays {
		if r.url != c.currentPrimary {
			ordered = append(ordered, r)
		}
	}
	eps := make([]pgns.Endpoint, len(ordered))
	for i, item := range ordered {
		ep := item.ep
		ep.Priority = uint16((i + 1) * 10)
		eps[i] = ep
	}
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Priority != eps[j].Priority {
			return eps[i].Priority < eps[j].Priority
		}
		return bytes.Compare(eps[i].RelayID[:], eps[j].RelayID[:]) < 0
	})
	return eps
}

func (c *pgnsController) buildSignedTx(txType uint8, leaf pgns.PortalLeafRecord) ([]byte, error) {
	parsed, err := leaf.ValidateInZone(c.zone)
	if err != nil {
		return nil, err
	}
	var nonce uint64
	if diff := pgns.RequiredPoWDifficulty(txType, parsed.Class); diff > 0 {
		rawLeaf, err := leaf.MarshalCanonical()
		if err != nil {
			return nil, err
		}
		nonce = pgns.MinePoW(txType, rawLeaf, diff)
	}
	tx := pgns.LeafTx{
		TxType:   txType,
		Leaf:     leaf,
		PoWNonce: nonce,
	}
	if err := tx.SignOwner(c.sitePriv); err != nil {
		return nil, err
	}
	return tx.MarshalCanonical()
}

func (c *pgnsController) submitTx(ctx context.Context, rawTx []byte) error {
	var lastErr error
	for _, baseURL := range c.sequencers {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/submit", bytes.NewReader(rawTx))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("sequencer %s rejected tx (%d): %s", baseURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return lastErr
}

func (c *pgnsController) waitForSeqConfirmed(ctx context.Context, targetSeq uint64) error {
	waitCtx, cancel := context.WithTimeout(ctx, pgnsEpochConfirmTimeout)
	defer cancel()
	ticker := time.NewTicker(pgnsSubmitRetryWait)
	defer ticker.Stop()
	for {
		_, leaf, _, err := c.fetchVerifiedResolve(waitCtx)
		if err == nil && leaf.Seq >= targetSeq {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for pgns seq %d confirmation: %w", targetSeq, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (c *pgnsController) start(parent context.Context, exposure *sdk.Exposure) {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return
	}
	workerCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	c.cancel = cancel
	c.exposure = exposure
	if c.probeFn == nil && exposure != nil {
		c.probeFn = exposure.ProbeRelayPGNS
	}
	c.mu.Unlock()

	c.wg.Add(1)
	go c.runHealthLoop(workerCtx)
	if c.acmeDir != "" {
		c.wg.Add(1)
		go c.runACMELoop(workerCtx)
	}
}

func (c *pgnsController) close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
	return nil
}

func (c *pgnsController) runHealthLoop(ctx context.Context) {
	defer c.wg.Done()
	for {
		delay := pgnsProbeBaseInterval + randomDuration(pgnsProbeJitterMax)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		c.probeOnce(ctx)
	}
}

func (c *pgnsController) probeOnce(ctx context.Context) {
	c.mu.Lock()
	relays := slices.Clone(c.relays)
	probe := c.probeFn
	c.mu.Unlock()
	if probe == nil {
		return
	}
	probeOK := make(map[string]bool, len(relays))
	for _, r := range relays {
		probeCtx, cancel := context.WithTimeout(ctx, pgnsProbeTimeout)
		probeOK[r.url] = probe(probeCtx, r.url) == nil
		cancel()
	}
	nextPrimary, seq, changed := c.evaluateFailover(c.nowFn().UTC(), probeOK)
	if !changed {
		return
	}
	log.Info().Str("fqdn", c.fqdn).Str("primary_relay", nextPrimary).Uint64("seq", seq).Msg("updating pgns primary relay")
	if err := c.publishAndConfirm(ctx, pgns.TxTypeUpdate, seq, false); err != nil {
		log.Warn().Err(err).Str("fqdn", c.fqdn).Msg("failed to publish pgns primary relay update")
	}
}

func (c *pgnsController) evaluateFailover(now time.Time, probeOK map[string]bool) (nextPrimary string, nextSeq uint64, changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.relays {
		if probeOK[r.url] {
			c.failCounts[r.url] = 0
		} else {
			c.failCounts[r.url]++
		}
	}
	if !c.hasLeaf {
		return "", 0, false
	}
	if c.failCounts[c.currentPrimary] >= pgnsFailThreshold {
		if candidate := c.pickHealthyStandbyLocked(probeOK); candidate != "" {
			c.currentPrimary = candidate
			c.lastFailoverAt = now
			c.failbackCooldown = pgnsFailbackCooldown + randomDuration(pgnsFailbackJitterMax)
			return candidate, c.currentLeaf.Seq + 1, true
		}
	}
	if c.currentPrimary != c.preferredPrimary && probeOK[c.preferredPrimary] {
		if !now.Before(c.lastFailoverAt.Add(c.failbackCooldown)) {
			c.currentPrimary = c.preferredPrimary
			c.lastFailoverAt = now
			return c.preferredPrimary, c.currentLeaf.Seq + 1, true
		}
	}
	return "", 0, false
}

func (c *pgnsController) pickHealthyStandbyLocked(probeOK map[string]bool) string {
	for _, r := range c.relays {
		if r.url != c.currentPrimary && probeOK[r.url] {
			return r.url
		}
	}
	return ""
}

func (c *pgnsController) runACMELoop(ctx context.Context) {
	defer c.wg.Done()
	for {
		wait := pgnsACMECheckInterval
		if c.shouldObtainACME(c.nowFn().UTC()) {
			if err := c.obtainACMECertificate(ctx); err != nil && ctx.Err() == nil {
				log.Warn().Err(err).Str("fqdn", c.fqdn).Msg("pgns acme certificate issuance failed")
				wait = 30 * time.Second
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *pgnsController) shouldObtainACME(now time.Time) bool {
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return true
	}
	cert, err := utils.ParseCertificatePEM(certPEM)
	if err != nil {
		return true
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != c.fqdn {
		return true
	}
	if cert.CheckSignatureFrom(cert) == nil {
		return true
	}
	return !cert.NotAfter.After(now.Add(pgnsACMERenewBefore))
}

func (c *pgnsController) obtainACMECertificate(ctx context.Context) error {
	client, accountURI, err := c.newLEGOClient(ctx)
	if err != nil {
		return err
	}
	nextKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(&nextKey.PublicKey)
	if err != nil {
		return err
	}
	nextSPKI := sha256.Sum256(spkiDER)
	provider := &pgnsDNS01Provider{
		ctx:        ctx,
		ctrl:       c,
		nextSPKI:   nextSPKI,
		accountURI: accountURI,
	}
	if err := client.Challenge.SetDNS01Provider(
		provider,
		dns01.DisableAuthoritativeNssPropagationRequirement(),
		dns01.WrapPreCheck(func(_, _, _ string, _ dns01.PreCheckFunc) (bool, error) {
			return true, ctx.Err()
		}),
	); err != nil {
		return err
	}
	obtained, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    []string{c.fqdn},
		PrivateKey: nextKey,
		Bundle:     true,
	})
	if err != nil {
		c.mu.Lock()
		c.acmeDigest = [32]byte{}
		c.nextSPKI = [32]byte{}
		c.mu.Unlock()
		return err
	}
	if err := utils.WriteFileAtomic(c.certFile, obtained.Certificate, 0o644); err != nil {
		return err
	}
	if err := utils.WriteFileAtomic(c.keyFile, obtained.PrivateKey, 0o600); err != nil {
		return err
	}
	if c.exposure != nil {
		if err := c.exposure.RefreshCertificates(ctx); err != nil {
			log.Warn().Err(err).Str("fqdn", c.fqdn).Msg("refresh live local tls certificate failed")
		}
	}
	return c.promoteACMEKey(ctx, nextSPKI, accountURI)
}

func (c *pgnsController) newLEGOClient(ctx context.Context) (*lego.Client, string, error) {
	acctKey, err := loadOrCreatePGNSACMEKey(filepath.Join(c.stateDir, pgnsACMEAccountKeyFile))
	if err != nil {
		return nil, "", err
	}
	regPath := filepath.Join(c.stateDir, pgnsACMERegistrationFile)
	var savedReg registration.Resource
	var regPtr *registration.Resource
	if ok, err := utils.ReadJSONFileIfExists(regPath, &savedReg); err == nil && ok {
		regPtr = &savedReg
	}
	user := &pgnsACMEUser{email: c.acmeEmail, key: acctKey, reg: regPtr}
	conf := lego.NewConfig(user)
	conf.CADirURL = c.acmeDir
	conf.Certificate.KeyType = certcrypto.EC256
	conf.HTTPClient.Transport = pgnsACMETransport{ctx: ctx, base: conf.HTTPClient.Transport}
	client, err := lego.NewClient(conf)
	if err != nil {
		return nil, "", err
	}
	if user.reg == nil {
		var reg *registration.Resource
		if c.acmeEABKID != "" {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  c.acmeEABKID,
				HmacEncoded:          c.acmeEABHMAC,
			})
		} else {
			reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		}
		if err != nil {
			return nil, "", err
		}
		user.reg = reg
		if err := utils.WriteJSONFile(regPath, reg, 0o600); err != nil {
			return nil, "", err
		}
	}
	return client, user.reg.URI, nil
}

func (c *pgnsController) stageACMEChallenge(ctx context.Context, digest, nextSPKI [32]byte, accountURI string) error {
	c.mu.Lock()
	if !c.hasLeaf {
		c.mu.Unlock()
		return errPGNSACMENoInitialLeaf
	}
	c.acmeAccountURI = accountURI
	c.acmeDigest = digest
	c.nextSPKI = nextSPKI
	seq := c.currentLeaf.Seq + 1
	c.mu.Unlock()
	return c.publishAndConfirm(ctx, pgns.TxTypeUpdate, seq, true)
}

func (c *pgnsController) promoteACMEKey(ctx context.Context, newSPKI [32]byte, accountURI string) error {
	c.mu.Lock()
	c.spkiSHA256 = newSPKI
	c.nextSPKI = [32]byte{}
	c.acmeDigest = [32]byte{}
	c.acmeAccountURI = accountURI
	seq := c.currentLeaf.Seq + 1
	c.mu.Unlock()
	return c.publishAndConfirm(ctx, pgns.TxTypeUpdate, seq, true)
}

func (c *pgnsController) clearACMEChallenge(ctx context.Context) error {
	c.mu.Lock()
	if c.acmeDigest == ([32]byte{}) {
		c.mu.Unlock()
		return nil
	}
	c.acmeDigest = [32]byte{}
	seq := c.currentLeaf.Seq + 1
	c.mu.Unlock()
	return c.publishAndConfirm(ctx, pgns.TxTypeUpdate, seq, true)
}

type pgnsDNS01Provider struct {
	ctx        context.Context
	ctrl       *pgnsController
	nextSPKI   [32]byte
	accountURI string
}

func (p *pgnsDNS01Provider) Present(_, _, keyAuth string) error {
	digest := sha256.Sum256([]byte(keyAuth))
	return p.ctrl.stageACMEChallenge(p.ctx, digest, p.nextSPKI, p.accountURI)
}

func (p *pgnsDNS01Provider) CleanUp(_, _, _ string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return p.ctrl.clearACMEChallenge(cleanupCtx)
}

type pgnsACMEUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *pgnsACMEUser) GetEmail() string                        { return u.email }
func (u *pgnsACMEUser) GetRegistration() *registration.Resource { return u.reg }
func (u *pgnsACMEUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type pgnsACMETransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t pgnsACMETransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(req.WithContext(t.ctx))
}

func loadOrCreatePGNSACMEKey(path string) (crypto.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := utils.WriteFileAtomic(path, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func resolveACMEEmail(explicit, fqdn string) string {
	if explicit != "" {
		return explicit
	}
	return "acme@" + fqdn
}

func resolveACMEIssuer(explicit, directory string) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSuffix(explicit, "."))
	}
	if directory == "" {
		return ""
	}
	parsed, err := url.Parse(directory)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
}

func randomDuration(maxDur time.Duration) time.Duration {
	if maxDur <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxDur)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
