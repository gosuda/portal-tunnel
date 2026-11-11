package gcloud

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"google.golang.org/api/dns/v1"

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
