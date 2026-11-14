package gcloud

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errGcloudProviderIsNil       = errors.New("gcloud provider is nil")
	errGcloudProjectIDIsRequired = errors.New("gcloud project id is required")
	errGcloudDNSServiceIsNil     = errors.New("gcloud dns service is nil")
)

const (
	defaultRecordTTL  = 60
	defaultPollPeriod = 2 * time.Second
)

type Config struct {
	ProjectID   string
	ManagedZone string
}

type Provider struct {
	cfg   Config
	zones *utils.Snapshot[map[string]string]
}

type runtimeConfig struct {
	ProjectID   string
	ManagedZone string
	HTTPClient  *http.Client
}

func New(cfg Config) *Provider {
	return &Provider{
		cfg: Config{
			ProjectID:   strings.TrimSpace(cfg.ProjectID),
			ManagedZone: strings.TrimSpace(cfg.ManagedZone),
		},
		zones: utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string]),
	}
}

func (p *Provider) Name() string {
	return "gcloud"
}

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errGcloudProviderIsNil
	}

	cfg := gcloud.NewDefaultConfig()
	return dnsrecord.NewChallengeProvider(ctx, cfg.PropagationTimeout, cfg.PollingInterval,
		func(ctx context.Context, name, value string) (dnsrecord.Cleanup, error) {
			return p.presentChallenge(ctx, cfg, name, value)
		}), nil
}

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errGcloudProviderIsNil
	}
	baseDomain, recordType, publicIP, err := dnsrecord.AddressRecordsInputs(baseDomain, publicIP)
	if err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range dnsrecord.ApexWildcard(baseDomain) {
		if err := ensureRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.ResourceRecordSet{
			Name:    fqdn(recordName),
			Type:    recordType,
			Ttl:     defaultRecordTTL,
			Rrdatas: []string{publicIP},
		}); err != nil {
			return fmt.Errorf("upsert gcloud %s record %s: %w", recordType, recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name, publicIP string) error {
	if p == nil {
		return errGcloudProviderIsNil
	}
	name, recordType, publicIP, err := dnsrecord.AddressRecordInputs(name, publicIP)
	if err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	if err := ensureRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.ResourceRecordSet{
		Name:    fqdn(name),
		Type:    recordType,
		Ttl:     defaultRecordTTL,
		Rrdatas: []string{publicIP},
	}); err != nil {
		return fmt.Errorf("upsert gcloud %s record %s: %w", recordType, name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecords(ctx context.Context, name string) error {
	if p == nil {
		return errGcloudProviderIsNil
	}
	name, err := dnsrecord.RecordName(name)
	if err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, errs := listDeleteAddressRecordsExisting(ctx, service, runtimeCfg.ProjectID, zone.Name, name)
	if len(existing) > 0 {
		if err := applyChange(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.Change{
			Deletions: existing,
		}); err != nil {
			errs = append(errs, fmt.Errorf("delete gcloud address records %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errGcloudProviderIsNil
	}
	name, value, err := dnsrecord.TXTInputs(name, value)
	if err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone.Name, name, "TXT")
	if err != nil {
		return fmt.Errorf("list gcloud TXT records %s: %w", name, err)
	}

	values, present := mergeEnsureTXTRecordValues(existing, value)
	if present {
		return nil
	}

	if err := replaceRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, existing, &dns.ResourceRecordSet{
		Name:    fqdn(name),
		Type:    "TXT",
		Ttl:     recordTTL(existing),
		Rrdatas: values,
	}); err != nil {
		return fmt.Errorf("upsert gcloud TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errGcloudProviderIsNil
	}
	name, matchPrefix, err := dnsrecord.TXTPrefixInputs(name, matchPrefix)
	if err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone.Name, name, "TXT")
	if err != nil {
		return fmt.Errorf("list gcloud TXT records %s: %w", name, err)
	}
	if len(existing) == 0 {
		return nil
	}

	remaining, removed := filterDeleteTXTRecordsRemaining(existing, matchPrefix)
	if !removed {
		return nil
	}
	if len(remaining) == 0 {
		if err := applyChange(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.Change{
			Deletions: existing,
		}); err != nil {
			return fmt.Errorf("delete gcloud TXT records %s: %w", name, err)
		}
		return nil
	}

	if err := replaceRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, existing, &dns.ResourceRecordSet{
		Name:    fqdn(name),
		Type:    "TXT",
		Ttl:     recordTTL(existing),
		Rrdatas: remaining,
	}); err != nil {
		return fmt.Errorf("delete gcloud TXT records %s: %w", name, err)
	}
	return nil
}

func listDeleteAddressRecordsExisting(ctx context.Context, service *dns.Service, projectID, zoneName, name string) ([]*dns.ResourceRecordSet, []error) {
	var existing []*dns.ResourceRecordSet
	var errs []error
	for _, recordType := range []string{"A", "AAAA"} {
		records, err := listRecordSets(ctx, service, projectID, zoneName, name, recordType)
		if err != nil {
			errs = append(errs, fmt.Errorf("list gcloud %s records %s: %w", recordType, name, err))
			continue
		}
		existing = append(existing, records...)
	}
	return existing, errs
}

func mergeEnsureTXTRecordValues(existing []*dns.ResourceRecordSet, value string) ([]string, bool) {
	values := make([]string, 0, len(existing)+1)
	seen := make(map[string]struct{}, len(existing)+1)
	for _, recordSet := range existing {
		for _, raw := range recordSet.Rrdatas {
			normalized := dnsrecord.TXTContent(raw)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			values = append(values, normalized)
		}
	}
	if _, ok := seen[value]; ok {
		return nil, true
	}
	return append(values, value), false
}

func filterDeleteTXTRecordsRemaining(existing []*dns.ResourceRecordSet, matchPrefix string) ([]string, bool) {
	remaining := make([]string, 0, len(existing))
	seen := make(map[string]struct{}, len(existing))
	removed := false
	for _, recordSet := range existing {
		var dropped bool
		remaining, dropped = appendFilterDeleteTXTRecordsValues(seen, remaining, recordSet.Rrdatas, matchPrefix)
		removed = removed || dropped
	}
	return remaining, removed
}

func appendFilterDeleteTXTRecordsValues(seen map[string]struct{}, remaining []string, rrdatas []string, matchPrefix string) ([]string, bool) {
	removed := false
	for _, raw := range rrdatas {
		normalized := dnsrecord.TXTContent(raw)
		if normalized == "" {
			continue
		}
		if strings.HasPrefix(normalized, matchPrefix) {
			removed = true
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		remaining = append(remaining, normalized)
	}
	return remaining, removed
}
func (p *Provider) presentChallenge(ctx context.Context, cfg *gcloud.Config, name, value string) (dnsrecord.Cleanup, error) {
	runtimeCfg, err := newRuntimeConfig(ctx, p.cfg)
	if err != nil {
		return nil, err
	}
	runtimeCfg.HTTPClient.Timeout = 30 * time.Second
	service, err := dns.NewService(ctx, option.WithHTTPClient(runtimeCfg.HTTPClient))
	if err != nil {
		return nil, err
	}
	managedZone, err := p.findManagedZone(ctx, service, runtimeCfg.ProjectID, name, runtimeCfg.ManagedZone, cfg.AllowPrivateZone)
	if err != nil {
		return nil, err
	}
	zone := managedZone.Name
	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone, name, "TXT")
	if err != nil {
		return nil, err
	}
	values := []string{}
	ttl := int64(cfg.TTL)
	for _, rr := range existing {
		ttl = rr.Ttl
		for _, raw := range rr.Rrdatas {
			if dnsrecord.TXTContent(raw) == value {
				return nil, nil
			}
			values = append(values, raw)
		}
	}
	cleanup := func(ctx context.Context) error {

		fresh, err := newRuntimeConfig(ctx, Config{ProjectID: runtimeCfg.ProjectID, ManagedZone: zone})
		if err != nil {
			return err
		}
		fresh.HTTPClient.Timeout = 30 * time.Second
		svc, err := dns.NewService(ctx, option.WithHTTPClient(fresh.HTTPClient))
		if err != nil {
			return err
		}
		return removeChallenge(ctx, svc, runtimeCfg.ProjectID, zone, name, value)
	}
	change := &dns.Change{Deletions: existing, Additions: []*dns.ResourceRecordSet{{Name: fqdn(name), Type: "TXT", Ttl: ttl, Rrdatas: append(values, value)}}}

	return cleanup, applyChallengeChange(ctx, service, runtimeCfg.ProjectID, zone, change)
}

func removeChallenge(ctx context.Context, service *dns.Service, project, zone, name, value string) error {
	existing, err := listRecordSets(ctx, service, project, zone, name, "TXT")
	if err != nil {
		return err
	}
	change := &dns.Change{}
	for _, rr := range existing {
		remaining := slices.DeleteFunc(slices.Clone(rr.Rrdatas), func(raw string) bool { return dnsrecord.TXTContent(raw) == value })
		if len(remaining) == len(rr.Rrdatas) {
			continue
		}
		change.Deletions = append(change.Deletions, rr)
		if len(remaining) > 0 {
			replacement := *rr
			replacement.Rrdatas = remaining
			change.Additions = append(change.Additions, &replacement)
		}
	}
	if len(change.Deletions) == 0 {
		return nil
	}
	return applyChallengeChange(ctx, service, project, zone, change)
}

func applyChallengeChange(ctx context.Context, service *dns.Service, project, zone string, change *dns.Change) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return applyChange(ctx, service, project, zone, change)
}

// The oauth2 ADC helper's metadata fallback ignores its context. Keep its file
// precedence and parsing, but use cancellable metadata discovery and tokens.
func defaultCredentials(ctx context.Context) (*google.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	explicit := filename != ""
	if !explicit {
		home, _ := os.UserHomeDir()
		filename = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		if runtime.GOOS == "windows" {
			filename = filepath.Join(os.Getenv("APPDATA"), "gcloud", "application_default_credentials.json")
		}
	}
	data, err := os.ReadFile(filename)
	if err == nil {
		//nolint:staticcheck // Operator-controlled ADC files intentionally support all existing credential types.
		return google.CredentialsFromJSON(ctx, data, dns.NdevClouddnsReadwriteScope)
	}
	if explicit {
		return nil, err
	}
	if !metadata.NewClient(nil).OnGCEWithContext(ctx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("gcloud application default credentials not found")
	}
	project, err := metadata.ProjectIDWithContext(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &google.Credentials{ProjectID: project, TokenSource: oauth2.ReuseTokenSourceWithExpiry(nil, metadataTokenSource{ctx: ctx}, 225*time.Second)}, nil
}

type metadataTokenSource struct{ ctx context.Context }

func (s metadataTokenSource) Token() (*oauth2.Token, error) {
	raw, err := metadata.GetWithContext(s.ctx, "instance/service-accounts/default/token?scopes="+url.QueryEscape(dns.NdevClouddnsReadwriteScope))
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" || token.ExpiresIn == 0 {
		return nil, fmt.Errorf("gcloud metadata returned an incomplete token")
	}
	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return &token, nil
}
func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errGcloudProviderIsNil
	}
	baseDomain, err = dnsrecord.BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, baseDomain)
	if err != nil {
		return "", "", "", err
	}
	managedZone := zone.Name
	zone, err = service.ManagedZones.Get(runtimeCfg.ProjectID, managedZone).Context(ctx).Do()
	if err != nil {
		return "", "", "", fmt.Errorf("get gcloud managed zone %s: %w", managedZone, err)
	}

	return statusEnsureDNSSECGcloudZone(ctx, service, runtimeCfg.ProjectID, managedZone, zone)
}

func enableDNSSEC(ctx context.Context, service *dns.Service, projectID, managedZone string) error {
	if service == nil {
		return errGcloudDNSServiceIsNil
	}

	operation, err := service.ManagedZones.Patch(projectID, managedZone, &dns.ManagedZone{
		DnssecConfig: &dns.ManagedZoneDnsSecConfig{
			State: "on",
		},
	}).Context(ctx).Do()
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(operation.Status), "done") {
		return nil
	}

	for {
		if !utils.SleepOrDone(ctx, defaultPollPeriod) {
			return ctx.Err()
		}
		operation, err = service.ManagedZoneOperations.Get(projectID, managedZone, operation.Id).Context(ctx).Do()
		if err != nil {
			return err
		}
		if strings.EqualFold(strings.TrimSpace(operation.Status), "done") {
			return nil
		}
	}
}

func listDNSKeys(ctx context.Context, service *dns.Service, projectID, managedZone string) ([]*dns.DnsKey, error) {
	if service == nil {
		return nil, errGcloudDNSServiceIsNil
	}

	keys := make([]*dns.DnsKey, 0, 2)
	err := service.DnsKeys.List(projectID, managedZone).DigestType("sha256,sha384,sha1").Pages(ctx, func(page *dns.DnsKeysListResponse) error {
		keys = append(keys, page.DnsKeys...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func dnssecStatusFromZone(zone *dns.ManagedZone, keys []*dns.DnsKey) (state, dsRecord, message string, err error) {
	state = strings.TrimSpace(dnssecState(zone))
	dsRecord = activeDSRecord(keys)
	if dsRecord != "" {
		message = "publish the DS record at the registrar after Cloud DNS zone signing is enabled"
	} else if strings.EqualFold(state, "on") || strings.EqualFold(state, "transfer") {
		message = "wait for the active Cloud DNS DS record before updating the registrar"
	}
	return state, dsRecord, message, nil
}

func activeDSRecord(keys []*dns.DnsKey) string {
	for _, key := range keys {
		if key == nil || !key.IsActive || !strings.EqualFold(strings.TrimSpace(key.Type), "keySigning") {
			continue
		}
		if ds, ok := dnsKeyDSRecord(key); ok {
			return ds
		}
	}
	return ""
}

func dnsKeyDSRecord(key *dns.DnsKey) (string, bool) {
	if key == nil {
		return "", false
	}

	algorithm, ok := dnssecAlgorithmCode(key.Algorithm)
	if !ok {
		return "", false
	}
	digest, ok := preferredDigest(key.Digests)
	if !ok {
		return "", false
	}
	digestType, ok := dnssecDigestTypeCode(digest.Type)
	if !ok {
		return "", false
	}

	return fmt.Sprintf("%d %d %d %s", key.KeyTag, algorithm, digestType, strings.TrimSpace(digest.Digest)), true
}

func preferredDigest(digests []*dns.DnsKeyDigest) (*dns.DnsKeyDigest, bool) {
	for _, candidate := range []string{"sha256", "sha384", "sha1"} {
		for _, digest := range digests {
			if digest == nil || !strings.EqualFold(strings.TrimSpace(digest.Type), candidate) || strings.TrimSpace(digest.Digest) == "" {
				continue
			}
			return digest, true
		}
	}
	return nil, false
}

func dnssecAlgorithmCode(raw string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rsasha1":
		return 5, true
	case "rsasha256":
		return 8, true
	case "rsasha512":
		return 10, true
	case "ecdsap256sha256":
		return 13, true
	case "ecdsap384sha384":
		return 14, true
	default:
		return 0, false
	}
}

func dnssecDigestTypeCode(raw string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sha1":
		return 1, true
	case "sha256":
		return 2, true
	case "sha384":
		return 4, true
	default:
		return 0, false
	}
}

func dnssecState(zone *dns.ManagedZone) string {
	if zone == nil || zone.DnssecConfig == nil {
		return ""
	}
	return zone.DnssecConfig.State
}

func refreshEnsureDNSSECGcloudZone(ctx context.Context, service *dns.Service, projectID, managedZone string, zone *dns.ManagedZone) (*dns.ManagedZone, error) {
	if currentState := strings.ToLower(strings.TrimSpace(dnssecState(zone))); currentState == "on" || currentState == "transfer" {
		return zone, nil
	}
	if err := enableDNSSEC(ctx, service, projectID, managedZone); err != nil {
		return nil, fmt.Errorf("enable gcloud dnssec: %w", err)
	}
	zone, err := service.ManagedZones.Get(projectID, managedZone).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("refresh gcloud managed zone %s: %w", managedZone, err)
	}
	return zone, nil
}

func statusEnsureDNSSECGcloudZone(ctx context.Context, service *dns.Service, projectID, managedZone string, zone *dns.ManagedZone) (string, string, string, error) {
	zone, err := refreshEnsureDNSSECGcloudZone(ctx, service, projectID, managedZone, zone)
	if err != nil {
		return "", "", "", err
	}
	keys, err := listDNSKeys(ctx, service, projectID, managedZone)
	if err != nil {
		return "", "", "", fmt.Errorf("list gcloud dnssec keys: %w", err)
	}
	return dnssecStatusFromZone(zone, keys)
}
func newRuntimeConfig(ctx context.Context, cfg Config) (runtimeConfig, error) {
	creds, err := defaultCredentials(ctx)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load gcloud credentials: %w", err)
	}

	projectID := strings.TrimSpace(cfg.ProjectID)
	projectID = cmp.Or(projectID, strings.TrimSpace(creds.ProjectID))
	if projectID == "" && metadata.NewClient(nil).OnGCEWithContext(ctx) {
		if detected, err := metadata.ProjectIDWithContext(ctx); err == nil {
			projectID = strings.TrimSpace(detected)
		}
	}
	if err := ctx.Err(); err != nil {
		return runtimeConfig{}, err
	}
	if projectID == "" {
		return runtimeConfig{}, errGcloudProjectIDIsRequired
	}

	return runtimeConfig{
		ProjectID:   projectID,
		ManagedZone: strings.TrimSpace(cfg.ManagedZone),
		HTTPClient:  oauth2.NewClient(ctx, creds.TokenSource),
	}, nil
}

func (p *Provider) newService(ctx context.Context, domain string) (*dns.Service, runtimeConfig, *dns.ManagedZone, error) {
	runtimeCfg, err := newRuntimeConfig(ctx, p.cfg)
	if err != nil {
		return nil, runtimeConfig{}, nil, err
	}

	service, err := dns.NewService(ctx, option.WithHTTPClient(runtimeCfg.HTTPClient))
	if err != nil {
		return nil, runtimeConfig{}, nil, fmt.Errorf("create gcloud dns service: %w", err)
	}

	zone, err := p.findManagedZone(ctx, service, runtimeCfg.ProjectID, domain, runtimeCfg.ManagedZone, false)
	if err != nil {
		return nil, runtimeConfig{}, nil, err
	}
	return service, runtimeCfg, zone, nil
}

func (p *Provider) findManagedZone(ctx context.Context, service *dns.Service, projectID, domain, explicit string, allowPrivate bool) (*dns.ManagedZone, error) {
	if service == nil {
		return nil, errGcloudDNSServiceIsNil
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		zone, err := service.ManagedZones.Get(projectID, trimmed).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("get gcloud managed zone %q: %w", trimmed, err)
		}
		if err := validateManagedZone(zone, domain, trimmed, allowPrivate); err != nil {
			return nil, err
		}
		if zoneDomain := utils.NormalizeHostname(zone.DnsName); zoneDomain != "" && zone.Name != "" && isPublicZone(zone) {
			p.cacheFindManagedZoneEntry(zoneDomain, zone.Name)
		}
		return zone, nil
	}

	return p.resolveFindManagedZoneCandidates(ctx, service, projectID, domain, candidates, allowPrivate)
}

func validateManagedZone(zone *dns.ManagedZone, domain, explicit string, allowPrivate bool) error {
	if zone == nil {
		return fmt.Errorf("gcloud managed zone %q is nil", explicit)
	}
	if !isPublicZone(zone) && !allowPrivate {
		return fmt.Errorf("gcloud managed zone %q is not public", explicit)
	}
	if zoneDomain := utils.NormalizeHostname(zone.DnsName); zoneDomain == "" || !utils.HostnameMatchesBaseDomain(domain, zoneDomain) {
		return fmt.Errorf("gcloud managed zone %q does not cover %s", explicit, domain)
	}
	return nil
}

func isPublicZone(zone *dns.ManagedZone) bool {
	if zone == nil {
		return false
	}
	visibility := strings.ToLower(strings.TrimSpace(zone.Visibility))
	return visibility == "" || visibility == "public"
}

func matchFindManagedZoneCandidate(zoneList []*dns.ManagedZone, candidate string, allowPrivate bool) *dns.ManagedZone {
	for _, zone := range zoneList {
		if (!isPublicZone(zone) && !allowPrivate) || utils.NormalizeHostname(zone.DnsName) != candidate {
			continue
		}
		return zone
	}
	return nil
}

func (p *Provider) searchFindManagedZoneCandidates(ctx context.Context, service *dns.Service, projectID string, candidates []string, allowPrivate bool) (*dns.ManagedZone, string, error) {
	for _, candidate := range candidates {
		if zoneName := p.zones.Load()[candidate]; zoneName != "" && !allowPrivate {
			return &dns.ManagedZone{Name: zoneName, DnsName: fqdn(candidate)}, candidate, nil
		}
		out, err := service.ManagedZones.List(projectID).DnsName(fqdn(candidate)).Context(ctx).Do()
		if err != nil {
			return nil, "", fmt.Errorf("list gcloud managed zones: %w", err)
		}
		if matched := matchFindManagedZoneCandidate(out.ManagedZones, candidate, allowPrivate); matched != nil {
			return matched, candidate, nil
		}
	}
	return nil, "", nil
}

func (p *Provider) cacheFindManagedZoneEntry(key, value string) {
	p.zones.UpdateCopy(func(zones *map[string]string) {
		if *zones == nil {
			*zones = make(map[string]string)
		}
		(*zones)[key] = value
	})
}

func (p *Provider) resolveFindManagedZoneCandidates(ctx context.Context, service *dns.Service, projectID, domain string, candidates []string, allowPrivate bool) (*dns.ManagedZone, error) {
	zone, candidate, err := p.searchFindManagedZoneCandidates(ctx, service, projectID, candidates, allowPrivate)
	if err != nil {
		return nil, err
	}
	if zone == nil {
		return nil, fmt.Errorf("no gcloud public managed zone found for %s", domain)
	}
	if zone.Name != "" && isPublicZone(zone) {
		p.cacheFindManagedZoneEntry(candidate, zone.Name)
	}
	return zone, nil
}
func ensureRecordSet(ctx context.Context, service *dns.Service, projectID, managedZone string, desired *dns.ResourceRecordSet) error {
	existing, err := listRecordSets(ctx, service, projectID, managedZone, desired.Name, desired.Type)
	if err != nil {
		return err
	}
	if len(existing) == 1 && sameRecordSet(existing[0], desired) {
		return nil
	}
	return replaceRecordSet(ctx, service, projectID, managedZone, existing, desired)
}

func replaceRecordSet(ctx context.Context, service *dns.Service, projectID, managedZone string, existing []*dns.ResourceRecordSet, desired *dns.ResourceRecordSet) error {
	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{desired},
	}
	if len(existing) > 0 {
		change.Deletions = existing
	}
	return applyChange(ctx, service, projectID, managedZone, change)
}

func applyChange(ctx context.Context, service *dns.Service, projectID, managedZone string, change *dns.Change) error {
	if service == nil {
		return errGcloudDNSServiceIsNil
	}

	result, err := service.Changes.Create(projectID, managedZone, change).Context(ctx).Do()
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(result.Status), "done") {
		return nil
	}

	for {
		if !utils.SleepOrDone(ctx, defaultPollPeriod) {
			return ctx.Err()
		}
		result, err = service.Changes.Get(projectID, managedZone, result.Id).Context(ctx).Do()
		if err != nil {
			return err
		}
		if strings.EqualFold(strings.TrimSpace(result.Status), "done") {
			return nil
		}
	}
}

func listRecordSets(ctx context.Context, service *dns.Service, projectID, managedZone, name, recordType string) ([]*dns.ResourceRecordSet, error) {
	if service == nil {
		return nil, errGcloudDNSServiceIsNil
	}

	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	name = fqdn(name)
	out, err := service.ResourceRecordSets.List(projectID, managedZone).Name(name).Type(recordType).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	filtered := make([]*dns.ResourceRecordSet, 0, len(out.Rrsets))
	for _, recordSet := range out.Rrsets {
		if !strings.EqualFold(strings.TrimSpace(recordSet.Name), name) || !strings.EqualFold(strings.TrimSpace(recordSet.Type), recordType) {
			continue
		}
		filtered = append(filtered, recordSet)
	}
	return filtered, nil
}

func sameRecordSet(current, desired *dns.ResourceRecordSet) bool {
	if current == nil || desired == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.Name), strings.TrimSpace(desired.Name)) || !strings.EqualFold(strings.TrimSpace(current.Type), strings.TrimSpace(desired.Type)) || current.Ttl != desired.Ttl {
		return false
	}

	currentValues := make(map[string]int, len(current.Rrdatas))
	for _, value := range current.Rrdatas {
		currentValues[dnsrecord.TXTContent(value)]++
	}
	for _, value := range desired.Rrdatas {
		normalized := dnsrecord.TXTContent(value)
		if currentValues[normalized] == 0 {
			return false
		}
		currentValues[normalized]--
	}
	for _, remaining := range currentValues {
		if remaining != 0 {
			return false
		}
	}
	return true
}

func recordTTL(recordSets []*dns.ResourceRecordSet) int64 {
	for _, recordSet := range recordSets {
		if recordSet != nil && recordSet.Ttl > 0 {
			return recordSet.Ttl
		}
	}
	return defaultRecordTTL
}

func fqdn(name string) string {
	normalized := utils.NormalizeHostname(name)
	if normalized == "" {
		return ""
	}
	return normalized + "."
}
