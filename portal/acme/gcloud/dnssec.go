package gcloud

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/dns/v1"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
