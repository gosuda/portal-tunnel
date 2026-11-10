package hetzner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	legohetzner "github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/exp/zoneutil"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errHetznerProviderIsNil             = errors.New("hetzner provider is nil")
	errHetznerAPITokenIsRequired        = errors.New("hetzner api token is required")
	errHetznerDNSDoesNotSupportProvider = errors.New("hetzner dns does not support provider-side dnssec signing; use a DNSSEC-capable provider for ENS gasless automation")
	errHetznerClientIsNil               = errors.New("hetzner client is nil")
	errRecordValueIsRequired            = errors.New("record value is required")
)

const defaultRecordTTL = 60

type Provider struct {
	apiToken string

	zones *utils.Snapshot[map[string]string]
}

func New(apiToken string) *Provider {
	return &Provider{
		apiToken: strings.TrimSpace(apiToken),
		zones:    utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string]),
	}
}

func (p *Provider) Name() string {
	return "hetzner"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errHetznerProviderIsNil
	}
	if p.apiToken == "" {
		return nil, errHetznerAPITokenIsRequired
	}

	cfg := legohetzner.NewDefaultConfig()
	cfg.APIToken = p.apiToken

	provider, err := legohetzner.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create hetzner lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errHetznerProviderIsNil
	}
	baseDomain, recordType, publicIP, err := dnsrecord.AddressRecordsInputs(baseDomain, publicIP)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range dnsrecord.ApexWildcard(baseDomain) {
		if err := ensureRecord(ctx, client, zone, recordName, hcloud.ZoneRRSetType(recordType), publicIP); err != nil {
			return fmt.Errorf("upsert hetzner %s record %s: %w", recordType, recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name, publicIP string) error {
	if p == nil {
		return errHetznerProviderIsNil
	}
	name, recordType, publicIP, err := dnsrecord.AddressRecordInputs(name, publicIP)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, hcloud.ZoneRRSetType(recordType), publicIP); err != nil {
		return fmt.Errorf("upsert hetzner %s record %s: %w", recordType, name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecords(ctx context.Context, name string) error {
	if p == nil {
		return errHetznerProviderIsNil
	}
	name, err := dnsrecord.RecordName(name)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	var deleteErr error
	for _, recordType := range []hcloud.ZoneRRSetType{hcloud.ZoneRRSetTypeA, hcloud.ZoneRRSetTypeAAAA} {
		if err := deleteRRSet(ctx, client, zone, name, recordType); err != nil {
			deleteErr = errors.Join(deleteErr, fmt.Errorf("delete hetzner %s record %s: %w", recordType, name, err))
		}
	}
	return deleteErr
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errHetznerProviderIsNil
	}
	name, value, err := dnsrecord.TXTInputs(name, value)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureTXTRecord(ctx, client, zone, name, value); err != nil {
		return fmt.Errorf("upsert hetzner TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errHetznerProviderIsNil
	}
	name, matchPrefix, err := dnsrecord.TXTPrefixInputs(name, matchPrefix)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteTXTRecords(ctx, client, zone, name, matchPrefix); err != nil {
		return fmt.Errorf("delete hetzner TXT records %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errHetznerProviderIsNil
	}
	_, err = dnsrecord.BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}
	if p.apiToken == "" {
		return "", "", "", errHetznerAPITokenIsRequired
	}
	return "", "", "", errHetznerDNSDoesNotSupportProvider
}

func (p *Provider) clientAndZone(ctx context.Context, domain string) (*hcloud.Client, *hcloud.Zone, error) {
	client, err := p.newClient()
	if err != nil {
		return nil, nil, err
	}
	zone, err := p.findZone(ctx, client, domain)
	if err != nil {
		return nil, nil, err
	}
	return client, zone, nil
}

func (p *Provider) newClient() (*hcloud.Client, error) {
	if p == nil {
		return nil, errHetznerProviderIsNil
	}
	if p.apiToken == "" {
		return nil, errHetznerAPITokenIsRequired
	}
	return hcloud.NewClient(
		hcloud.WithToken(p.apiToken),
		hcloud.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		hcloud.WithPollOpts(hcloud.PollOpts{BackoffFunc: hcloud.ConstantBackoff(2 * time.Second)}),
	), nil
}

func (p *Provider) findZone(ctx context.Context, client *hcloud.Client, domain string) (*hcloud.Zone, error) {
	if client == nil {
		return nil, errHetznerClientIsNil
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)
	if zoneName, ok := lookupFindZoneCache(p.zones.Load(), candidates); ok {
		return &hcloud.Zone{Name: zoneName}, nil
	}
	return searchFindZoneCandidates(ctx, p, client, candidates, domain)
}

func lookupFindZoneCache(cached map[string]string, candidates []string) (string, bool) {
	for _, candidate := range candidates {
		if zoneName := cached[candidate]; zoneName != "" {
			return zoneName, true
		}
	}
	return "", false
}

func searchFindZoneCandidates(ctx context.Context, p *Provider, client *hcloud.Client, candidates []string, domain string) (*hcloud.Zone, error) {
	for _, candidate := range candidates {
		zone, err := fetchFindZoneCandidate(ctx, p, client, candidate)
		if err != nil {
			return nil, err
		}
		if zone != nil {
			return zone, nil
		}
	}
	return nil, fmt.Errorf("no hetzner zone found for %s", domain)
}

func fetchFindZoneCandidate(ctx context.Context, p *Provider, client *hcloud.Client, candidate string) (*hcloud.Zone, error) {
	zone, _, err := client.Zone.GetByName(ctx, candidate)
	if err != nil {
		return nil, fmt.Errorf("get hetzner zone %s: %w", candidate, err)
	}
	if zone == nil {
		return nil, nil
	}
	zoneName := utils.NormalizeBaseDomain(zone.Name)
	if zoneName == "" {
		return nil, nil
	}
	storeFindZoneEntry(p, candidate, zoneName)
	return zone, nil
}

func storeFindZoneEntry(p *Provider, candidate, zoneName string) {
	p.zones.UpdateCopy(func(cached *map[string]string) {
		if *cached == nil {
			*cached = make(map[string]string)
		}
		(*cached)[candidate] = zoneName
	})
}

func ensureRecord(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, fqdn string, recordType hcloud.ZoneRRSetType, value string) error {
	recordName, err := dnsrecord.RelativeName("hetzner", fqdn, zone.Name)
	if err != nil {
		return err
	}
	if value, err = normalizeRecordValueHetzner(value); err != nil {
		return err
	}
	desired := []hcloud.ZoneRRSetRecord{{Value: value}}

	existing, _, err := client.Zone.GetRRSetByNameAndType(ctx, zone, recordName, recordType)
	if err != nil {
		return err
	}
	if existing == nil {
		ttl := defaultRecordTTL
		return createRecordHetzner(ctx, client, zone, hcloud.ZoneRRSetCreateOpts{
			Name:    recordName,
			Type:    recordType,
			TTL:     &ttl,
			Records: desired,
		})
	}
	return replaceRecordHetzner(ctx, client, existing, desired)
}

func normalizeRecordValueHetzner(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errRecordValueIsRequired
	}
	return value, nil
}

func createRecordHetzner(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, opts hcloud.ZoneRRSetCreateOpts) error {
	result, _, err := client.Zone.CreateRRSet(ctx, zone, opts)
	if err != nil {
		return err
	}
	return waitAction(ctx, client, result.Action)
}

func replaceRecordHetzner(ctx context.Context, client *hcloud.Client, existing *hcloud.ZoneRRSet, desired []hcloud.ZoneRRSetRecord) error {
	if sameRecords(existing.Records, desired) {
		return nil
	}
	action, _, err := client.Zone.SetRRSetRecords(ctx, existing, hcloud.ZoneRRSetSetRecordsOpts{Records: desired})
	if err != nil {
		return err
	}
	return waitAction(ctx, client, action)
}

func ensureTXTRecord(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, fqdn, value string) error {
	recordName, err := dnsrecord.RelativeName("hetzner", fqdn, zone.Name)
	if err != nil {
		return err
	}
	formatted := zoneutil.FormatTXTRecord(value)
	desired := []hcloud.ZoneRRSetRecord{{Value: formatted}}

	existing, _, err := client.Zone.GetRRSetByNameAndType(ctx, zone, recordName, hcloud.ZoneRRSetTypeTXT)
	if err != nil {
		return err
	}
	if existing == nil {
		return createTXTRecordHetzner(ctx, client, zone, recordName, desired)
	}
	return appendTXTRecordHetzner(ctx, client, existing, desired, value)
}

func createTXTRecordHetzner(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, recordName string, desired []hcloud.ZoneRRSetRecord) error {
	ttl := defaultRecordTTL
	result, _, err := client.Zone.CreateRRSet(ctx, zone, hcloud.ZoneRRSetCreateOpts{
		Name:    recordName,
		Type:    hcloud.ZoneRRSetTypeTXT,
		TTL:     &ttl,
		Records: desired,
	})
	if err != nil {
		return err
	}
	return waitAction(ctx, client, result.Action)
}

func appendTXTRecordHetzner(ctx context.Context, client *hcloud.Client, existing *hcloud.ZoneRRSet, desired []hcloud.ZoneRRSetRecord, value string) error {
	for _, record := range existing.Records {
		if txtContent(record.Value) == value {
			return nil
		}
	}

	ttl := defaultRecordTTL
	action, _, err := client.Zone.AddRRSetRecords(ctx, existing, hcloud.ZoneRRSetAddRecordsOpts{
		Records: desired,
		TTL:     &ttl,
	})
	if err != nil {
		return err
	}
	return waitAction(ctx, client, action)
}

func deleteRRSet(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, fqdn string, recordType hcloud.ZoneRRSetType) error {
	recordName, err := dnsrecord.RelativeName("hetzner", fqdn, zone.Name)
	if err != nil {
		return err
	}
	existing, _, err := client.Zone.GetRRSetByNameAndType(ctx, zone, recordName, recordType)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}

	result, _, err := client.Zone.DeleteRRSet(ctx, existing)
	if err != nil {
		return err
	}
	return waitAction(ctx, client, result.Action)
}

func deleteTXTRecords(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, fqdn, matchPrefix string) error {
	recordName, err := dnsrecord.RelativeName("hetzner", fqdn, zone.Name)
	if err != nil {
		return err
	}
	existing, _, err := client.Zone.GetRRSetByNameAndType(ctx, zone, recordName, hcloud.ZoneRRSetTypeTXT)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	remaining := filterRemainingTXTRecordsHetzner(existing.Records, matchPrefix)
	if len(remaining) == len(existing.Records) {
		return nil
	}
	return storeRemainingTXTRecordsHetzner(ctx, client, existing, remaining)
}

func filterRemainingTXTRecordsHetzner(records []hcloud.ZoneRRSetRecord, matchPrefix string) []hcloud.ZoneRRSetRecord {
	remaining := make([]hcloud.ZoneRRSetRecord, 0, len(records))
	for _, record := range records {
		if strings.HasPrefix(txtContent(record.Value), matchPrefix) {
			continue
		}
		remaining = append(remaining, record)
	}
	return remaining
}

func storeRemainingTXTRecordsHetzner(ctx context.Context, client *hcloud.Client, existing *hcloud.ZoneRRSet, remaining []hcloud.ZoneRRSetRecord) error {
	if len(remaining) == 0 {
		result, _, err := client.Zone.DeleteRRSet(ctx, existing)
		if err != nil {
			return err
		}
		return waitAction(ctx, client, result.Action)
	}

	action, _, err := client.Zone.SetRRSetRecords(ctx, existing, hcloud.ZoneRRSetSetRecordsOpts{Records: remaining})
	if err != nil {
		return err
	}
	return waitAction(ctx, client, action)
}

func sameRecords(current, desired []hcloud.ZoneRRSetRecord) bool {
	if len(current) != len(desired) {
		return false
	}
	current = slices.Clone(current)
	desired = slices.Clone(desired)
	slices.SortFunc(current, compareRecords)
	slices.SortFunc(desired, compareRecords)
	for i := range current {
		if current[i] != desired[i] {
			return false
		}
	}
	return true
}

func compareRecords(a, b hcloud.ZoneRRSetRecord) int {
	if cmp := strings.Compare(a.Value, b.Value); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.Comment, b.Comment)
}

func txtContent(raw string) string {
	return zoneutil.ParseTXTRecord(strings.TrimSpace(raw))
}

func waitAction(ctx context.Context, client *hcloud.Client, action *hcloud.Action) error {
	if action == nil {
		return nil
	}
	return client.Action.WaitFor(ctx, action)
}
