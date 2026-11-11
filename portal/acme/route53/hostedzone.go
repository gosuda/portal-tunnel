package route53

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newClient(ctx context.Context, cfg Config) (*awsroute53.Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(regionOrDefault(cfg.Region)),
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		loadOptions = append(loadOptions, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return awsroute53.NewFromConfig(awsCfg), nil
}

func (p *Provider) clientAndZone(ctx context.Context, name string) (*awsroute53.Client, string, error) {
	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return nil, "", err
	}
	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return nil, "", err
	}
	return client, hostedZoneID, nil
}

func (p *Provider) findHostedZoneID(ctx context.Context, client *awsroute53.Client, domain string) (string, error) {
	if explicitZoneID := normalizeZoneID(p.cfg.HostedZoneID); explicitZoneID != "" {
		return explicitZoneID, nil
	}
	if client == nil {
		return "", errRoute53ClientIsNil
	}

	candidates := utils.DomainCandidates(domain)
	if len(candidates) == 0 {
		return "", fmt.Errorf("invalid base domain for hosted zone lookup: %q", domain)
	}

	if zoneID, ok := lookupFindHostedZoneIDCache(p.zones.Load(), candidates); ok {
		return zoneID, nil
	}

	zonesByName, err := listFindHostedZoneIDZonesByName(ctx, client)
	if err != nil {
		return "", err
	}

	if len(zonesByName) > 0 {
		p.zones.UpdateCopy(func(zones *map[string]string) {
			if *zones == nil {
				*zones = make(map[string]string)
			}
			maps.Copy((*zones), zonesByName)
		})
	}

	if zoneID, ok := matchFindHostedZoneIDCandidate(candidates, zonesByName); ok {
		return zoneID, nil
	}

	return "", fmt.Errorf("no route53 public hosted zone found for %s", domain)
}

func (p *Provider) awsRegion() string {
	if p == nil {
		return defaultAWSRegion
	}
	return regionOrDefault(p.cfg.Region)
}

func regionOrDefault(region string) string {
	if trimmed := strings.TrimSpace(region); trimmed != "" {
		return trimmed
	}
	return defaultAWSRegion
}

func validateConfig(cfg Config) error {
	switch {
	case cfg.SessionToken != "" && (cfg.AccessKeyID == "" || cfg.SecretAccessKey == ""):
		return errRoute53SessionTokenRequiresAccessKey
	case (cfg.AccessKeyID == "") != (cfg.SecretAccessKey == ""):
		return errRoute53AccessKeyIDAndSecret
	}
	return nil
}

func normalizeZoneID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	return strings.TrimPrefix(trimmed, "/hostedzone/")
}

func lookupFindHostedZoneIDCache(zones map[string]string, candidates []string) (string, bool) {
	for _, candidate := range candidates {
		if zoneID := zones[candidate]; zoneID != "" {
			return zoneID, true
		}
	}
	return "", false
}

func listFindHostedZoneIDZonesByName(ctx context.Context, client *awsroute53.Client) (map[string]string, error) {
	zonesByName := make(map[string]string)
	paginator := awsroute53.NewListHostedZonesPaginator(client, &awsroute53.ListHostedZonesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}
		for _, hostedZone := range page.HostedZones {
			if hostedZone.Config != nil && hostedZone.Config.PrivateZone {
				continue
			}
			zoneName := utils.NormalizeHostname(aws.ToString(hostedZone.Name))
			zoneID := normalizeZoneID(aws.ToString(hostedZone.Id))
			if zoneName == "" || zoneID == "" {
				continue
			}
			zonesByName[zoneName] = zoneID
		}
	}
	return zonesByName, nil
}

func matchFindHostedZoneIDCandidate(candidates []string, zonesByName map[string]string) (string, bool) {
	for _, candidate := range candidates {
		if zoneID, ok := zonesByName[candidate]; ok {
			return zoneID, true
		}
	}
	return "", false
}
