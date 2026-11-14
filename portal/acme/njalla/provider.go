package njalla

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	legonjalla "github.com/go-acme/lego/v4/providers/dns/njalla"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errNjallaProviderIsNil                   = errors.New("njalla provider is nil")
	errNjallaTokenIsRequired                 = errors.New("njalla token is required")
	errNjallaDnssecAutomationNotSupportedUse = errors.New("njalla dnssec automation is not supported; use a DNSSEC-capable provider for ENS gasless automation")
	errNjallaClientIsNil                     = errors.New("njalla client is nil")
	errRecordContentIsRequired               = errors.New("record content is required")
	errNjallaRecordIDIsRequired              = errors.New("njalla record id is required")
)

const (
	apiEndpoint      = "https://njal.la/api/1/"
	defaultRecordTTL = 60
	defaultTimeout   = 30 * time.Second
)

type Provider struct {
	token string
	zones *utils.Snapshot[map[string]string]
}

func New(token string) *Provider {
	return &Provider{
		token: strings.TrimSpace(token),
		zones: utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string]),
	}
}

func (p *Provider) Name() string {
	return "njalla"
}

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errNjallaProviderIsNil
	}
	if p.token == "" {
		return nil, errNjallaTokenIsRequired
	}

	cfg := legonjalla.NewDefaultConfig()
	client := &apiClient{token: p.token, endpoint: apiEndpoint, httpClient: cfg.HTTPClient}
	return dnsrecord.NewChallengeProvider(ctx, cfg.PropagationTimeout, cfg.PollingInterval,
		func(ctx context.Context, fqdn, value string) (dnsrecord.Cleanup, error) {
			zone, err := p.findZone(ctx, client, fqdn)
			if err != nil {
				return nil, err
			}
			return presentChallenge(ctx, client, zone, fqdn, value, cfg.TTL)
		}), nil
}

func presentChallenge(ctx context.Context, client *apiClient, zone, fqdn, value string, ttl int) (dnsrecord.Cleanup, error) {
	name, err := dnsrecord.RelativeName("njalla", fqdn, zone)
	if err != nil {
		return nil, err
	}
	existing, err := listRecords(ctx, client, zone, fqdn, "TXT")
	if err != nil {
		return nil, err
	}
	for _, rec := range existing {
		if dnsrecord.TXTContent(rec.Content) == value {
			return nil, nil
		}
	}
	var recordID string
	cleanup := func(ctx context.Context) error {
		records, err := listRecords(ctx, client, zone, fqdn, "TXT")
		if err != nil {
			return err
		}
		for _, rec := range records {
			if dnsrecord.TXTContent(rec.Content) != value || (recordID != "" && rec.ID.String() != recordID) {
				continue
			}
			if err := client.removeRecord(ctx, rec.ID.String(), zone); err != nil {
				return err
			}
		}
		return nil
	}
	rec, err := client.addRecord(ctx, record{Domain: zone, Name: name, Type: "TXT", TTL: ttl, Content: value})
	if rec != nil {
		recordID = rec.ID.String()
	}
	// A failed response does not prove the write failed. The preceding read
	// established absence, so cleanup can recover the exact value if necessary.
	return cleanup, err
}

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errNjallaProviderIsNil
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
		if err := ensureRecord(ctx, client, zone, recordName, recordType, publicIP); err != nil {
			return fmt.Errorf("upsert njalla %s record %s: %w", recordType, recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name, publicIP string) error {
	if p == nil {
		return errNjallaProviderIsNil
	}
	name, recordType, publicIP, err := dnsrecord.AddressRecordInputs(name, publicIP)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, recordType, publicIP); err != nil {
		return fmt.Errorf("upsert njalla %s record %s: %w", recordType, name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecords(ctx context.Context, name string) error {
	if p == nil {
		return errNjallaProviderIsNil
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
	for _, recordType := range []string{"A", "AAAA"} {
		if err := deleteRecords(ctx, client, zone, name, recordType, ""); err != nil {
			deleteErr = errors.Join(deleteErr, fmt.Errorf("delete njalla %s record %s: %w", recordType, name, err))
		}
	}
	return deleteErr
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errNjallaProviderIsNil
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
		return fmt.Errorf("upsert njalla TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errNjallaProviderIsNil
	}
	name, matchPrefix, err := dnsrecord.TXTPrefixInputs(name, matchPrefix)
	if err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "TXT", matchPrefix); err != nil {
		return fmt.Errorf("delete njalla TXT records %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errNjallaProviderIsNil
	}
	_, err = dnsrecord.BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}
	if p.token == "" {
		return "", "", "", errNjallaTokenIsRequired
	}
	return "", "", "", errNjallaDnssecAutomationNotSupportedUse
}

func (p *Provider) clientAndZone(ctx context.Context, domain string) (*apiClient, string, error) {
	client, err := p.newClient()
	if err != nil {
		return nil, "", err
	}
	zone, err := p.findZone(ctx, client, domain)
	if err != nil {
		return nil, "", err
	}
	return client, zone, nil
}

func (p *Provider) newClient() (*apiClient, error) {
	if p == nil {
		return nil, errNjallaProviderIsNil
	}
	if p.token == "" {
		return nil, errNjallaTokenIsRequired
	}
	return &apiClient{
		token:      p.token,
		endpoint:   apiEndpoint,
		httpClient: utils.NewHTTPClient(utils.WithHTTPTimeout(defaultTimeout)),
	}, nil
}

func (p *Provider) findZone(ctx context.Context, client *apiClient, domain string) (string, error) {
	if client == nil {
		return "", errNjallaClientIsNil
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	var lastErr error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if zone := zones[candidate]; zone != "" {
			return zone, nil
		}
		if _, err := client.listRecords(ctx, candidate); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			lastErr = err
			continue
		}
		p.zones.UpdateCopy(func(zones *map[string]string) {
			if *zones == nil {
				*zones = make(map[string]string)
			}
			(*zones)[candidate] = candidate
		})
		return candidate, nil
	}
	if lastErr != nil {
		return "", fmt.Errorf("no njalla zone found for %s: %w", domain, lastErr)
	}
	return "", fmt.Errorf("no njalla zone found for %s", domain)
}

func ensureRecord(ctx context.Context, client *apiClient, zone, fqdn, recordType, content string) error {
	recordName, err := dnsrecord.RelativeName("njalla", fqdn, zone)
	if err != nil {
		return err
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errRecordContentIsRequired
	}

	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}
	needsAdd, err := pruneRecordsNjalla(ctx, client, zone, existing, content)
	if err != nil {
		return err
	}
	if !needsAdd {
		return nil
	}
	return client.insertRecordNjalla(ctx, zone, recordName, recordType, content)
}

func ensureTXTRecord(ctx context.Context, client *apiClient, zone, fqdn, value string) error {
	recordName, err := dnsrecord.RelativeName("njalla", fqdn, zone)
	if err != nil {
		return err
	}
	existing, err := listRecords(ctx, client, zone, fqdn, "TXT")
	if err != nil {
		return err
	}
	for _, record := range existing {
		if dnsrecord.TXTContent(record.Content) == value {
			return nil
		}
	}
	_, err = client.addRecord(ctx, record{
		Domain:  zone,
		Name:    recordName,
		Type:    "TXT",
		TTL:     defaultRecordTTL,
		Content: value,
	})
	return err
}

func deleteRecords(ctx context.Context, client *apiClient, zone, fqdn, recordType, matchPrefix string) error {
	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}
	for _, record := range existing {
		if matchPrefix != "" && !strings.HasPrefix(dnsrecord.TXTContent(record.Content), matchPrefix) {
			continue
		}
		if err := client.removeRecord(ctx, record.ID.String(), zone); err != nil {
			return err
		}
	}
	return nil
}

func listRecords(ctx context.Context, client *apiClient, zone, fqdn, recordType string) ([]record, error) {
	if client == nil {
		return nil, errNjallaClientIsNil
	}
	recordName, err := dnsrecord.RelativeName("njalla", fqdn, zone)
	if err != nil {
		return nil, err
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))

	records, err := client.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	filtered := make([]record, 0, len(records))
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Type), recordType) || !dnsrecord.NameMatches(record.Name, recordName, fqdn, zone) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, nil
}
