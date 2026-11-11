package gcloud

import (
	"context"
	"strings"

	"google.golang.org/api/dns/v1"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
