package vultr

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	legovultr "github.com/go-acme/lego/v4/providers/dns/vultr"
	"github.com/vultr/govultr/v3"
	"golang.org/x/oauth2"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultRecordTTL = 60

type Provider struct {
	apiKey string

	zones *utils.Snapshot[map[string]string]
}

func New(apiKey string) *Provider {
	return &Provider{
		apiKey: strings.TrimSpace(apiKey),
		zones:  utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
	}
}

func (p *Provider) Name() string {
	return "vultr"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("vultr provider is nil")
	}
	if p.apiKey == "" {
		return nil, errors.New("vultr api key is required")
	}

	cfg := legovultr.NewDefaultConfig()
	cfg.APIKey = p.apiKey

	provider, err := legovultr.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create vultr lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, err := p.newClient(ctx)
	if err != nil {
		return err
	}
	zone, err := p.findZone(ctx, client, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range []string{baseDomain, "*." + baseDomain} {
		if err := ensureRecord(ctx, client, zone, recordName, "A", strings.TrimSpace(publicIPv4)); err != nil {
			return fmt.Errorf("upsert vultr A record %s: %w", recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
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
	if err := ensureRecord(ctx, client, zone, name, "A", strings.TrimSpace(publicIPv4)); err != nil {
		return fmt.Errorf("upsert vultr A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "A", ""); err != nil {
		return fmt.Errorf("delete vultr A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
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
		return fmt.Errorf("upsert vultr TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
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
	if err := deleteRecords(ctx, client, zone, name, "TXT", matchPrefix); err != nil {
		return fmt.Errorf("delete vultr TXT records %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, _ uint16, _, _, content string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
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
	if err := ensureRecord(ctx, client, zone, name, "HTTPS", content); err != nil {
		return fmt.Errorf("upsert vultr HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("vultr provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "HTTPS", ""); err != nil {
		return fmt.Errorf("delete vultr HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("vultr provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
	}

	client, err := p.newClient(ctx)
	if err != nil {
		return "", "", "", err
	}
	zone, err := p.findZone(ctx, client, baseDomain)
	if err != nil {
		return "", "", "", err
	}

	domain, _, err := client.Domain.Get(ctx, zone)
	if err != nil {
		return "", "", "", fmt.Errorf("get vultr domain %s: %w", zone, err)
	}
	if domain != nil {
		state = strings.TrimSpace(domain.DNSSec)
	}
	if !strings.EqualFold(state, "enabled") {
		if err := client.Domain.Update(ctx, zone, "enabled"); err != nil {
			return "", "", "", fmt.Errorf("enable vultr dnssec: %w", err)
		}
		domain, _, err = client.Domain.Get(ctx, zone)
		if err != nil {
			return "", "", "", fmt.Errorf("refresh vultr domain %s: %w", zone, err)
		}
		state = "enabled"
		if domain != nil && strings.TrimSpace(domain.DNSSec) != "" {
			state = strings.TrimSpace(domain.DNSSec)
		}
	}

	records, _, err := client.Domain.GetDNSSec(ctx, zone)
	if err != nil {
		return "", "", "", fmt.Errorf("get vultr dnssec records: %w", err)
	}
	dsRecord = preferredDSRecord(records)
	if dsRecord != "" {
		message = "publish the DS record at the registrar after Vultr zone signing is enabled"
	} else if strings.EqualFold(state, "enabled") {
		message = "wait for the active Vultr DS record before updating the registrar"
	}
	return state, dsRecord, message, nil
}

func (p *Provider) clientAndZone(ctx context.Context, domain string) (*govultr.Client, string, error) {
	client, err := p.newClient(ctx)
	if err != nil {
		return nil, "", err
	}
	zone, err := p.findZone(ctx, client, domain)
	if err != nil {
		return nil, "", err
	}
	return client, zone, nil
}

func (p *Provider) newClient(ctx context.Context) (*govultr.Client, error) {
	if p == nil {
		return nil, errors.New("vultr provider is nil")
	}
	if p.apiKey == "" {
		return nil, errors.New("vultr api key is required")
	}
	return govultr.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: p.apiKey}))), nil
}

func (p *Provider) findZone(ctx context.Context, client *govultr.Client, domain string) (string, error) {
	if client == nil {
		return "", errors.New("vultr client is nil")
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	for _, candidate := range candidates {
		if zone := zones[candidate]; zone != "" {
			return zone, nil
		}
	}

	listOptions := &govultr.ListOptions{PerPage: 100}
	for {
		domains, meta, _, err := client.Domain.List(ctx, listOptions)
		if err != nil {
			return "", fmt.Errorf("list vultr domains: %w", err)
		}
		for _, item := range domains {
			zone := utils.NormalizeBaseDomain(item.Domain)
			for _, candidate := range candidates {
				if zone != candidate {
					continue
				}
				p.zones.UpdateCopy(func(zones *map[string]string) {
					if *zones == nil {
						*zones = make(map[string]string)
					}
					(*zones)[candidate] = zone
				})
				return zone, nil
			}
		}
		if meta == nil || meta.Links == nil || meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}

	return "", fmt.Errorf("no vultr domain found for %s", domain)
}

func ensureRecord(ctx context.Context, client *govultr.Client, zone, fqdn, recordType, data string) error {
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return err
	}
	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}
	for _, record := range existing {
		if strings.TrimSpace(record.Data) == data {
			return nil
		}
	}
	if len(existing) > 0 {
		name := recordName
		return client.DomainRecord.Update(ctx, zone, existing[0].ID, &govultr.DomainRecordUpdateReq{
			Name: &name,
			Type: recordType,
			Data: data,
			TTL:  defaultRecordTTL,
		})
	}

	_, _, err = client.DomainRecord.Create(ctx, zone, &govultr.DomainRecordCreateReq{
		Name: recordName,
		Type: recordType,
		Data: data,
		TTL:  defaultRecordTTL,
	})
	return err
}

func ensureTXTRecord(ctx context.Context, client *govultr.Client, zone, fqdn, value string) error {
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return err
	}
	existing, err := listRecords(ctx, client, zone, fqdn, "TXT")
	if err != nil {
		return err
	}
	for _, record := range existing {
		if txtContent(record.Data) == value {
			return nil
		}
	}

	_, _, err = client.DomainRecord.Create(ctx, zone, &govultr.DomainRecordCreateReq{
		Name: recordName,
		Type: "TXT",
		Data: value,
		TTL:  defaultRecordTTL,
	})
	return err
}

func deleteRecords(ctx context.Context, client *govultr.Client, zone, fqdn, recordType, matchPrefix string) error {
	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}
	for _, record := range existing {
		if matchPrefix != "" && !strings.HasPrefix(txtContent(record.Data), matchPrefix) {
			continue
		}
		if err := client.DomainRecord.Delete(ctx, zone, record.ID); err != nil {
			return err
		}
	}
	return nil
}

func listRecords(ctx context.Context, client *govultr.Client, zone, fqdn, recordType string) ([]govultr.DomainRecord, error) {
	if client == nil {
		return nil, errors.New("vultr client is nil")
	}
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return nil, err
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	listOptions := &govultr.ListOptions{PerPage: 100}

	var filtered []govultr.DomainRecord
	for {
		records, meta, _, err := client.DomainRecord.List(ctx, zone, listOptions)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if !strings.EqualFold(strings.TrimSpace(record.Type), recordType) || !sameRecordName(record.Name, recordName, fqdn, zone) {
				continue
			}
			filtered = append(filtered, record)
		}
		if meta == nil || meta.Links == nil || meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}
	return filtered, nil
}

func relativeRecordName(fqdn, zone string) (string, error) {
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)
	if fqdn == "" {
		return "", errors.New("record name is required")
	}
	if zone == "" {
		return "", errors.New("vultr zone is required")
	}
	if fqdn == zone {
		return "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("hostname %q is outside vultr zone %q", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

func sameRecordName(recordName, expected, fqdn, zone string) bool {
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

func txtContent(raw string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(raw))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(raw), "\"")
}

func preferredDSRecord(records []string) string {
	candidates := make(map[string]string, len(records))
	first := ""
	for _, raw := range records {
		ds := normalizeDSRecord(raw)
		if ds == "" {
			continue
		}
		if first == "" {
			first = ds
		}
		fields := strings.Fields(ds)
		if len(fields) < 4 {
			continue
		}
		candidates[fields[2]] = ds
	}
	for _, digestType := range []string{"2", "4", "1"} {
		if record := candidates[digestType]; record != "" {
			return record
		}
	}
	return first
}

func normalizeDSRecord(raw string) string {
	fields := strings.Fields(strings.TrimSpace(raw))
	for i, field := range fields {
		if strings.EqualFold(field, "DS") && len(fields) >= i+5 {
			return strings.Join(fields[i+1:i+5], " ")
		}
	}
	if len(fields) == 4 {
		return strings.Join(fields, " ")
	}
	return ""
}
