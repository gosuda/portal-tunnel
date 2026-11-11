package acme

import (
	"fmt"
	"path/filepath"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/cloudflare"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/embedded"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/gcloud"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/hetzner"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/njalla"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/route53"
	"github.com/gosuda/portal-tunnel/v2/portal/acme/vultr"
	"github.com/gosuda/portal-tunnel/v2/types"
)

func newDNSProvider(providerType string, cfg Config) (dnsProvider, error) {
	switch providerType {
	case TypeEmbedded:
		return embedded.New(embedded.Config{
			BaseDomain: cfg.BaseDomain,
			ListenAddr: fmt.Sprintf(":%d", cfg.EmbeddedDNSPort),
			KeyPath:    filepath.Join(cfg.KeyDir, types.DNSSECKeyFileName),
		})
	case TypeCloudflare:
		return cloudflare.New(cfg.CloudflareToken), nil
	case TypeGCloud:
		return gcloud.New(gcloud.Config{
			ProjectID:   cfg.GCPProjectID,
			ManagedZone: cfg.GCPManagedZone,
		}), nil
	case TypeHetzner:
		return hetzner.New(cfg.HetznerAPIToken), nil
	case TypeNjalla:
		return njalla.New(cfg.NjallaToken), nil
	case TypeRoute53:
		return route53.New(route53.Config{
			AccessKeyID:     cfg.AWSAccessKeyID,
			SecretAccessKey: cfg.AWSSecretAccessKey,
			SessionToken:    cfg.AWSSessionToken,
			Region:          cfg.AWSRegion,
			HostedZoneID:    cfg.AWSHostedZoneID,
			KMSKeyARN:       cfg.AWSKMSKeyARN,
		}), nil
	case TypeVultr:
		return vultr.New(cfg.VultrAPIKey), nil
	default:
		return nil, fmt.Errorf("unsupported acme dns provider: %q", providerType)
	}
}
