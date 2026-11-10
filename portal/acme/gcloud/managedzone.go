package gcloud

import (
	"cmp"
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newRuntimeConfig(ctx context.Context, cfg Config) (runtimeConfig, error) {
	creds, err := google.FindDefaultCredentials(ctx, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("load gcloud credentials: %w", err)
	}

	projectID := strings.TrimSpace(cfg.ProjectID)
	projectID = cmp.Or(projectID, strings.TrimSpace(creds.ProjectID))
	if projectID == "" && metadata.OnGCE() {
		if detected, err := metadata.ProjectIDWithContext(ctx); err == nil {
			projectID = strings.TrimSpace(detected)
		}
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

	zone, err := p.findManagedZone(ctx, service, runtimeCfg.ProjectID, domain, runtimeCfg.ManagedZone)
	if err != nil {
		return nil, runtimeConfig{}, nil, err
	}
	return service, runtimeCfg, zone, nil
}

func (p *Provider) findManagedZone(ctx context.Context, service *dns.Service, projectID, domain, explicit string) (*dns.ManagedZone, error) {
	if service == nil {
		return nil, errGcloudDNSServiceIsNil
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	if zoneName, candidate, ok := lookupFindManagedZoneCache(p.zones.Load(), candidates); ok {
		return &dns.ManagedZone{Name: zoneName, DnsName: fqdn(candidate)}, nil
	}

	if trimmed := strings.TrimSpace(explicit); trimmed != "" {
		return p.resolveFindManagedZoneExplicit(ctx, service, projectID, domain, trimmed)
	}

	return p.resolveFindManagedZoneCandidates(ctx, service, projectID, domain, candidates)
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

func isPublicZone(zone *dns.ManagedZone) bool {
	if zone == nil {
		return false
	}
	visibility := strings.ToLower(strings.TrimSpace(zone.Visibility))
	return visibility == "" || visibility == "public"
}

func lookupFindManagedZoneCache(zones map[string]string, candidates []string) (string, string, bool) {
	for _, candidate := range candidates {
		if zoneName := zones[candidate]; zoneName != "" {
			return zoneName, candidate, true
		}
	}
	return "", "", false
}

func fetchFindManagedZoneExplicit(ctx context.Context, service *dns.Service, projectID, domain, explicit string) (*dns.ManagedZone, error) {
	zone, err := service.ManagedZones.Get(projectID, explicit).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get gcloud managed zone %q: %w", explicit, err)
	}
	if err := validateManagedZone(zone, domain, explicit); err != nil {
		return nil, err
	}
	return zone, nil
}

func matchFindManagedZoneCandidate(zoneList []*dns.ManagedZone, candidate string) *dns.ManagedZone {
	for _, zone := range zoneList {
		if !isPublicZone(zone) || utils.NormalizeHostname(zone.DnsName) != candidate {
			continue
		}
		return zone
	}
	return nil
}

func searchFindManagedZoneCandidates(ctx context.Context, service *dns.Service, projectID string, candidates []string) (*dns.ManagedZone, string, error) {
	for _, candidate := range candidates {
		out, err := service.ManagedZones.List(projectID).DnsName(fqdn(candidate)).Context(ctx).Do()
		if err != nil {
			return nil, "", fmt.Errorf("list gcloud managed zones: %w", err)
		}
		if matched := matchFindManagedZoneCandidate(out.ManagedZones, candidate); matched != nil {
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

func (p *Provider) resolveFindManagedZoneExplicit(ctx context.Context, service *dns.Service, projectID, domain, explicit string) (*dns.ManagedZone, error) {
	zone, err := fetchFindManagedZoneExplicit(ctx, service, projectID, domain, explicit)
	if err != nil {
		return nil, err
	}
	if zoneDomain := utils.NormalizeHostname(zone.DnsName); zoneDomain != "" && zone.Name != "" {
		p.cacheFindManagedZoneEntry(zoneDomain, zone.Name)
	}
	return zone, nil
}

func (p *Provider) resolveFindManagedZoneCandidates(ctx context.Context, service *dns.Service, projectID, domain string, candidates []string) (*dns.ManagedZone, error) {
	zone, candidate, err := searchFindManagedZoneCandidates(ctx, service, projectID, candidates)
	if err != nil {
		return nil, err
	}
	if zone == nil {
		return nil, fmt.Errorf("no gcloud public managed zone found for %s", domain)
	}
	if zone.Name != "" {
		p.cacheFindManagedZoneEntry(candidate, zone.Name)
	}
	return zone, nil
}
