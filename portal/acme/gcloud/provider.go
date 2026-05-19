package gcloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gosuda/portal-tunnel/v2/utils"
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
		zones: utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
	}
}

func (p *Provider) Name() string {
	return "gcloud"
}

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("gcloud provider is nil")
	}

	runtimeCfg, err := newRuntimeConfig(ctx, p.cfg)
	if err != nil {
		return nil, err
	}

	cfg := gcloud.NewDefaultConfig()
	cfg.Project = runtimeCfg.ProjectID
	cfg.ZoneID = runtimeCfg.ManagedZone
	cfg.HTTPClient = runtimeCfg.HTTPClient

	provider, err := gcloud.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create gcloud lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range []string{baseDomain, "*." + baseDomain} {
		if err := ensureRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.ResourceRecordSet{
			Name:    fqdn(recordName),
			Type:    "A",
			Ttl:     defaultRecordTTL,
			Rrdatas: []string{strings.TrimSpace(publicIPv4)},
		}); err != nil {
			return fmt.Errorf("upsert gcloud A record %s: %w", recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	if err := ensureRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.ResourceRecordSet{
		Name:    fqdn(name),
		Type:    "A",
		Ttl:     defaultRecordTTL,
		Rrdatas: []string{strings.TrimSpace(publicIPv4)},
	}); err != nil {
		return fmt.Errorf("upsert gcloud A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone.Name, name, "A")
	if err != nil {
		return fmt.Errorf("list gcloud A records %s: %w", name, err)
	}
	if len(existing) == 0 {
		return nil
	}
	if err := applyChange(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.Change{
		Deletions: existing,
	}); err != nil {
		return fmt.Errorf("delete gcloud A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone.Name, name, "TXT")
	if err != nil {
		return fmt.Errorf("list gcloud TXT records %s: %w", name, err)
	}

	values := make([]string, 0, len(existing)+1)
	seen := make(map[string]struct{}, len(existing)+1)
	for _, recordSet := range existing {
		for _, raw := range recordSet.Rrdatas {
			normalized := txtContent(raw)
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
		return nil
	}
	values = append(values, value)

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
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
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

	remaining := make([]string, 0, len(existing))
	seen := make(map[string]struct{}, len(existing))
	removed := false
	for _, recordSet := range existing {
		for _, raw := range recordSet.Rrdatas {
			normalized := txtContent(raw)
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
	}
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

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, _ uint16, _, _, content string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("https record content is required")
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	if err := ensureRecordSet(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.ResourceRecordSet{
		Name:    fqdn(name),
		Type:    "HTTPS",
		Ttl:     defaultRecordTTL,
		Rrdatas: []string{content},
	}); err != nil {
		return fmt.Errorf("upsert gcloud HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("gcloud provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	service, runtimeCfg, zone, err := p.newService(ctx, name)
	if err != nil {
		return err
	}

	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone.Name, name, "HTTPS")
	if err != nil {
		return fmt.Errorf("list gcloud HTTPS records %s: %w", name, err)
	}
	if len(existing) == 0 {
		return nil
	}
	if err := applyChange(ctx, service, runtimeCfg.ProjectID, zone.Name, &dns.Change{
		Deletions: existing,
	}); err != nil {
		return fmt.Errorf("delete gcloud HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("gcloud provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
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

	currentState := strings.ToLower(strings.TrimSpace(dnssecState(zone)))
	if currentState != "on" && currentState != "transfer" {
		if err := enableDNSSEC(ctx, service, runtimeCfg.ProjectID, managedZone); err != nil {
			return "", "", "", fmt.Errorf("enable gcloud dnssec: %w", err)
		}
		zone, err = service.ManagedZones.Get(runtimeCfg.ProjectID, managedZone).Context(ctx).Do()
		if err != nil {
			return "", "", "", fmt.Errorf("refresh gcloud managed zone %s: %w", managedZone, err)
		}
	}

	keys, err := listDNSKeys(ctx, service, runtimeCfg.ProjectID, managedZone)
	if err != nil {
		return "", "", "", fmt.Errorf("list gcloud dnssec keys: %w", err)
	}

	return dnssecStatusFromZone(zone, keys)
}

func newRuntimeConfig(ctx context.Context, cfg Config) (runtimeConfig, error) {
	creds, err := google.FindDefaultCredentials(ctx, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load gcloud credentials: %w", err)
	}

	projectID := strings.TrimSpace(cfg.ProjectID)
	if projectID == "" {
		projectID = strings.TrimSpace(creds.ProjectID)
	}
	if projectID == "" && metadata.OnGCE() {
		if detected, err := metadata.ProjectIDWithContext(ctx); err == nil {
			projectID = strings.TrimSpace(detected)
		}
	}
	if projectID == "" {
		return runtimeConfig{}, errors.New("gcloud project id is required")
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

	zone, err := p.findManagedZone(ctx, service, runtimeCfg.ProjectID, domain, runtimeCfg.ManagedZone)
	if err != nil {
		return nil, runtimeConfig{}, nil, err
	}
	return service, runtimeCfg, zone, nil
}

func (p *Provider) findManagedZone(ctx context.Context, service *dns.Service, projectID, domain, explicit string) (*dns.ManagedZone, error) {
	if service == nil {
		return nil, errors.New("gcloud dns service is nil")
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	for _, candidate := range candidates {
		if zoneName := zones[candidate]; zoneName != "" {
			return &dns.ManagedZone{Name: zoneName, DnsName: fqdn(candidate)}, nil
		}
	}

	if explicit = strings.TrimSpace(explicit); explicit != "" {
		zone, err := service.ManagedZones.Get(projectID, explicit).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("get gcloud managed zone %q: %w", explicit, err)
		}
		if err := validateManagedZone(zone, domain, explicit); err != nil {
			return nil, err
		}
		if zoneDomain := utils.NormalizeHostname(zone.DnsName); zoneDomain != "" && zone.Name != "" {
			p.zones.UpdateCopy(func(zones *map[string]string) {
				if *zones == nil {
					*zones = make(map[string]string)
				}
				(*zones)[zoneDomain] = zone.Name
			})
		}
		return zone, nil
	}

	for _, candidate := range candidates {
		out, err := service.ManagedZones.List(projectID).DnsName(fqdn(candidate)).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("list gcloud managed zones: %w", err)
		}
		for _, zone := range out.ManagedZones {
			if !isPublicZone(zone) || utils.NormalizeHostname(zone.DnsName) != candidate {
				continue
			}
			if zone.Name != "" {
				p.zones.UpdateCopy(func(zones *map[string]string) {
					if *zones == nil {
						*zones = make(map[string]string)
					}
					(*zones)[candidate] = zone.Name
				})
			}
			return zone, nil
		}
	}

	return nil, fmt.Errorf("no gcloud public managed zone found for %s", domain)
}

func validateManagedZone(zone *dns.ManagedZone, domain, explicit string) error {
	if zone == nil {
		return fmt.Errorf("gcloud managed zone %q is nil", explicit)
	}
	if !isPublicZone(zone) {
		return fmt.Errorf("gcloud managed zone %q is not public", explicit)
	}
	if zoneDomain := utils.NormalizeHostname(zone.DnsName); zoneDomain == "" || !utils.HostnameMatchesBaseDomain(domain, zoneDomain) {
		return fmt.Errorf("gcloud managed zone %q does not cover %s", explicit, domain)
	}
	return nil
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
		return errors.New("gcloud dns service is nil")
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
		return nil, errors.New("gcloud dns service is nil")
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

func enableDNSSEC(ctx context.Context, service *dns.Service, projectID, managedZone string) error {
	if service == nil {
		return errors.New("gcloud dns service is nil")
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
		return nil, errors.New("gcloud dns service is nil")
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

func sameRecordSet(current, desired *dns.ResourceRecordSet) bool {
	if current == nil || desired == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.Name), strings.TrimSpace(desired.Name)) || !strings.EqualFold(strings.TrimSpace(current.Type), strings.TrimSpace(desired.Type)) || current.Ttl != desired.Ttl {
		return false
	}

	currentValues := make(map[string]int, len(current.Rrdatas))
	for _, value := range current.Rrdatas {
		currentValues[txtContent(value)]++
	}
	for _, value := range desired.Rrdatas {
		normalized := txtContent(value)
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

func isPublicZone(zone *dns.ManagedZone) bool {
	if zone == nil {
		return false
	}
	visibility := strings.ToLower(strings.TrimSpace(zone.Visibility))
	return visibility == "" || visibility == "public"
}

func fqdn(name string) string {
	normalized := utils.NormalizeHostname(name)
	if normalized == "" {
		return ""
	}
	return normalized + "."
}

func txtContent(raw string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(raw))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(raw), "\"")
}
