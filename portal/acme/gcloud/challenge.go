package gcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

func (p *Provider) presentChallenge(ctx context.Context, cfg *gcloud.Config, name, value string) (dnsrecord.Cleanup, error) {
	runtimeCfg, err := newRuntimeConfig(ctx, p.cfg)
	if err != nil {
		return nil, err
	}
	runtimeCfg.HTTPClient.Timeout = 30 * time.Second
	service, err := dns.NewService(ctx, option.WithHTTPClient(runtimeCfg.HTTPClient))
	if err != nil {
		return nil, err
	}
	managedZone, err := p.findManagedZone(ctx, service, runtimeCfg.ProjectID, name, runtimeCfg.ManagedZone, cfg.AllowPrivateZone)
	if err != nil {
		return nil, err
	}
	zone := managedZone.Name
	existing, err := listRecordSets(ctx, service, runtimeCfg.ProjectID, zone, name, "TXT")
	if err != nil {
		return nil, err
	}
	values := []string{}
	ttl := int64(cfg.TTL)
	for _, rr := range existing {
		ttl = rr.Ttl
		for _, raw := range rr.Rrdatas {
			if dnsrecord.TXTContent(raw) == value {
				return nil, nil
			}
			values = append(values, raw)
		}
	}
	cleanup := func(ctx context.Context) error {
		// OAuth sources retain their creation context, so cleanup must create its own.
		fresh, err := newRuntimeConfig(ctx, Config{ProjectID: runtimeCfg.ProjectID, ManagedZone: zone})
		if err != nil {
			return err
		}
		fresh.HTTPClient.Timeout = 30 * time.Second
		svc, err := dns.NewService(ctx, option.WithHTTPClient(fresh.HTTPClient))
		if err != nil {
			return err
		}
		return removeChallenge(ctx, svc, runtimeCfg.ProjectID, zone, name, value)
	}
	change := &dns.Change{Deletions: existing, Additions: []*dns.ResourceRecordSet{{Name: fqdn(name), Type: "TXT", Ttl: ttl, Rrdatas: append(values, value)}}}
	// Even an unsuccessful write may have reached the server.
	return cleanup, applyChallengeChange(ctx, service, runtimeCfg.ProjectID, zone, change)
}

func removeChallenge(ctx context.Context, service *dns.Service, project, zone, name, value string) error {
	existing, err := listRecordSets(ctx, service, project, zone, name, "TXT")
	if err != nil {
		return err
	}
	change := &dns.Change{}
	for _, rr := range existing {
		remaining := slices.DeleteFunc(slices.Clone(rr.Rrdatas), func(raw string) bool { return dnsrecord.TXTContent(raw) == value })
		if len(remaining) == len(rr.Rrdatas) {
			continue
		}
		change.Deletions = append(change.Deletions, rr)
		if len(remaining) > 0 {
			replacement := *rr
			replacement.Rrdatas = remaining
			change.Additions = append(change.Additions, &replacement)
		}
	}
	if len(change.Deletions) == 0 {
		return nil
	}
	return applyChallengeChange(ctx, service, project, zone, change)
}

func applyChallengeChange(ctx context.Context, service *dns.Service, project, zone string, change *dns.Change) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return applyChange(ctx, service, project, zone, change)
}

// The oauth2 ADC helper's metadata fallback ignores its context. Keep its file
// precedence and parsing, but use cancellable metadata discovery and tokens.
func defaultCredentials(ctx context.Context) (*google.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	explicit := filename != ""
	if !explicit {
		home, _ := os.UserHomeDir()
		filename = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		if runtime.GOOS == "windows" {
			filename = filepath.Join(os.Getenv("APPDATA"), "gcloud", "application_default_credentials.json")
		}
	}
	data, err := os.ReadFile(filename)
	if err == nil {
		//nolint:staticcheck // Operator-controlled ADC files intentionally support all existing credential types.
		return google.CredentialsFromJSON(ctx, data, dns.NdevClouddnsReadwriteScope)
	}
	if explicit {
		return nil, err
	}
	if !metadata.NewClient(nil).OnGCEWithContext(ctx) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("gcloud application default credentials not found")
	}
	project, err := metadata.ProjectIDWithContext(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &google.Credentials{ProjectID: project, TokenSource: oauth2.ReuseTokenSourceWithExpiry(nil, metadataTokenSource{ctx: ctx}, 225*time.Second)}, nil
}

type metadataTokenSource struct{ ctx context.Context }

func (s metadataTokenSource) Token() (*oauth2.Token, error) {
	raw, err := metadata.GetWithContext(s.ctx, "instance/service-accounts/default/token?scopes="+url.QueryEscape(dns.NdevClouddnsReadwriteScope))
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" || token.ExpiresIn == 0 {
		return nil, fmt.Errorf("gcloud metadata returned an incomplete token")
	}
	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return &token, nil
}
