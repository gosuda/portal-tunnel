package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	legohetzner "github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/exp/zoneutil"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultRecordTTL = 60

type Provider struct {
	apiToken string

	zones *utils.Snapshot[map[string]string]
}

func New(apiToken string) *Provider {
	return &Provider{
		apiToken: strings.TrimSpace(apiToken),
		zones:    utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
	}
}

func (p *Provider) Name() string {
	return "hetzner"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("hetzner provider is nil")
	}
	if p.apiToken == "" {
		return nil, errors.New("hetzner api token is required")
	}

	cfg := legohetzner.NewDefaultConfig()
	cfg.APIToken = p.apiToken

	provider, err := legohetzner.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create hetzner lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range []string{baseDomain, "*." + baseDomain} {
		if err := ensureRecord(ctx, client, zone, recordName, hcloud.ZoneRRSetTypeA, strings.TrimSpace(publicIPv4)); err != nil {
			return fmt.Errorf("upsert hetzner A record %s: %w", recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, hcloud.ZoneRRSetTypeA, strings.TrimSpace(publicIPv4)); err != nil {
		return fmt.Errorf("upsert hetzner A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRRSet(ctx, client, zone, name, hcloud.ZoneRRSetTypeA); err != nil {
		return fmt.Errorf("delete hetzner A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
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
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
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

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, _ uint16, _, _, content string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("https record content is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, hcloud.ZoneRRSetTypeHTTPS, content); err != nil {
		return fmt.Errorf("upsert hetzner HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("hetzner provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRRSet(ctx, client, zone, name, hcloud.ZoneRRSetTypeHTTPS); err != nil {
		return fmt.Errorf("delete hetzner HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("hetzner provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
	}
	if p.apiToken == "" {
		return "", "", "", errors.New("hetzner api token is required")
	}
	return "", "", "", errors.New("hetzner dns does not support provider-side dnssec signing; use a DNSSEC-capable provider for ENS gasless automation")
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
		return nil, errors.New("hetzner provider is nil")
	}
	if p.apiToken == "" {
		return nil, errors.New("hetzner api token is required")
	}
	return hcloud.NewClient(
		hcloud.WithToken(p.apiToken),
		hcloud.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		hcloud.WithPollOpts(hcloud.PollOpts{BackoffFunc: hcloud.ConstantBackoff(2 * time.Second)}),
	), nil
}

func (p *Provider) findZone(ctx context.Context, client *hcloud.Client, domain string) (*hcloud.Zone, error) {
	if client == nil {
		return nil, errors.New("hetzner client is nil")
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	for _, candidate := range candidates {
		if zoneName := zones[candidate]; zoneName != "" {
			return &hcloud.Zone{Name: zoneName}, nil
		}
	}

	for _, candidate := range candidates {
		zone, _, err := client.Zone.GetByName(ctx, candidate)
		if err != nil {
			return nil, fmt.Errorf("get hetzner zone %s: %w", candidate, err)
		}
		if zone == nil {
			continue
		}
		zoneName := utils.NormalizeBaseDomain(zone.Name)
		if zoneName == "" {
			continue
		}
		p.zones.UpdateCopy(func(zones *map[string]string) {
			if *zones == nil {
				*zones = make(map[string]string)
			}
			(*zones)[candidate] = zoneName
		})
		return zone, nil
	}

	return nil, fmt.Errorf("no hetzner zone found for %s", domain)
}

func ensureRecord(ctx context.Context, client *hcloud.Client, zone *hcloud.Zone, fqdn string, recordType hcloud.ZoneRRSetType, value string) error {
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("record value is required")
	}
	desired := []hcloud.ZoneRRSetRecord{{Value: value}}

	existing, _, err := client.Zone.GetRRSetByNameAndType(ctx, zone, recordName, recordType)
	if err != nil {
		return err
	}
	if existing == nil {
		ttl := defaultRecordTTL
		result, _, err := client.Zone.CreateRRSet(ctx, zone, hcloud.ZoneRRSetCreateOpts{
			Name:    recordName,
			Type:    recordType,
			TTL:     &ttl,
			Records: desired,
		})
		if err != nil {
			return err
		}
		return waitAction(ctx, client, result.Action)
	}
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
	recordName, err := relativeRecordName(fqdn, zone)
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
	recordName, err := relativeRecordName(fqdn, zone)
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
	recordName, err := relativeRecordName(fqdn, zone)
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

	remaining := existing.Records[:0]
	for _, record := range existing.Records {
		if strings.HasPrefix(txtContent(record.Value), matchPrefix) {
			continue
		}
		remaining = append(remaining, record)
	}
	if len(remaining) == len(existing.Records) {
		return nil
	}
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

func relativeRecordName(fqdn string, zone *hcloud.Zone) (string, error) {
	fqdn = utils.NormalizeHostname(fqdn)
	if fqdn == "" {
		return "", errors.New("record name is required")
	}
	if zone == nil {
		return "", errors.New("hetzner zone is required")
	}
	zoneName := utils.NormalizeBaseDomain(zone.Name)
	if zoneName == "" && zone.ID != 0 {
		return "", errors.New("hetzner zone name is required")
	}
	if fqdn == zoneName {
		return "@", nil
	}
	suffix := "." + zoneName
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("hostname %q is outside hetzner zone %q", fqdn, zoneName)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
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
