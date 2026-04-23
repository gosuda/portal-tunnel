package acme

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/cloudflare"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/gcloud"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/route53"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	TypeCloudflare = "cloudflare"
	TypeGCloud     = "gcloud"
	TypeRoute53    = "route53"
)

type DNSProvider interface {
	Name() string
	ChallengeProvider(ctx context.Context) (challenge.Provider, error)
	EnsureAddressRecords(ctx context.Context, baseDomain string, publicIPs utils.PublicIPs) error
	EnsureAddressRecord(ctx context.Context, name string, publicIPs utils.PublicIPs) error
	DeleteAddressRecord(ctx context.Context, name string) error
	EnsureTXTRecord(ctx context.Context, name, value string) error
	DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error
	EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error)
}

func NewDNSProvider(providerType string, cfg Config) (DNSProvider, error) {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case "":
		return nil, nil
	case TypeCloudflare:
		return cloudflare.New(cfg.CloudflareToken), nil
	case TypeGCloud:
		return gcloud.New(gcloud.Config{
			ProjectID:   cfg.GCPProjectID,
			ManagedZone: cfg.GCPManagedZone,
		}), nil
	case TypeRoute53:
		return route53.New(route53.Config{
			AccessKeyID:     cfg.AWSAccessKeyID,
			SecretAccessKey: cfg.AWSSecretAccessKey,
			SessionToken:    cfg.AWSSessionToken,
			Region:          cfg.AWSRegion,
			HostedZoneID:    cfg.AWSHostedZoneID,
			KMSKeyARN:       cfg.AWSKMSKeyARN,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported acme dns provider: %q", providerType)
	}
}
