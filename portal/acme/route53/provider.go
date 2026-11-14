package route53

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errRoute53ProviderIsNil                  = errors.New("route53 provider is nil")
	errRoute53DnssecRequiresActiveKeySigning = errors.New("route53 dnssec requires an ACTIVE key-signing key")
	errRoute53ClientIsNil                    = errors.New("route53 client is nil")
	errHostedZoneIDIsRequired                = errors.New("hosted zone id is required")
	errRoute53SessionTokenRequiresAccessKey  = errors.New("route53 session token requires access key id and secret access key")
	errRoute53AccessKeyIDAndSecret           = errors.New("route53 access key id and secret access key must be supplied together")
	errRoute53DnssecRequiresAwsDnssecKms     = errors.New("route53 dnssec requires AWS_DNSSEC_KMS_KEY_ARN when no active key-signing key exists")
)

const (
	defaultAWSRegion     = "us-east-1"
	defaultDNSSECKSKName = "portal_ksk"
)

type Config struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	HostedZoneID    string
	KMSKeyARN       string
}

type Provider struct {
	cfg   Config
	zones *utils.Snapshot[map[string]string]
}

func New(cfg Config) *Provider {
	return &Provider{
		cfg: Config{
			AccessKeyID:     strings.TrimSpace(cfg.AccessKeyID),
			SecretAccessKey: strings.TrimSpace(cfg.SecretAccessKey),
			SessionToken:    strings.TrimSpace(cfg.SessionToken),
			Region:          strings.TrimSpace(cfg.Region),
			HostedZoneID:    normalizeZoneID(cfg.HostedZoneID),
			KMSKeyARN:       strings.TrimSpace(cfg.KMSKeyARN),
		},
		zones: utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string]),
	}
}

func (p *Provider) Name() string {
	return "route53"
}

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errRoute53ProviderIsNil
	}
	if err := validateConfig(p.cfg); err != nil {
		return nil, err
	}

	cfg := route53.NewDefaultConfig()
	cfg.AccessKeyID = p.cfg.AccessKeyID
	cfg.SecretAccessKey = p.cfg.SecretAccessKey
	cfg.SessionToken = p.cfg.SessionToken
	cfg.Region = p.awsRegion()
	cfg.HostedZoneID = p.cfg.HostedZoneID

	return dnsrecord.NewChallengeProvider(ctx, cfg.PropagationTimeout, cfg.PollingInterval,
		func(ctx context.Context, name, value string) (dnsrecord.Cleanup, error) {
			return presentChallenge(ctx, cfg, name, value)
		}), nil
}

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errRoute53ProviderIsNil
	}
	baseDomain, recordType, publicIP, err := dnsrecord.AddressRecordsInputs(baseDomain, publicIP)
	if err != nil {
		return err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range dnsrecord.ApexWildcard(baseDomain) {
		if err := upsertRecord(ctx, client, hostedZoneID, recordName, route53types.RRType(recordType), []string{publicIP}, "Managed by Portal ACME"); err != nil {
			return fmt.Errorf("upsert route53 %s record %s: %w", recordType, recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name, publicIP string) error {
	if p == nil {
		return errRoute53ProviderIsNil
	}
	name, recordType, publicIP, err := dnsrecord.AddressRecordInputs(name, publicIP)
	if err != nil {
		return err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := upsertRecord(ctx, client, hostedZoneID, name, route53types.RRType(recordType), []string{publicIP}, "Managed by Portal ACME"); err != nil {
		return fmt.Errorf("upsert route53 %s record %s: %w", recordType, name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecords(ctx context.Context, name string) error {
	if p == nil {
		return errRoute53ProviderIsNil
	}
	name, err := dnsrecord.RecordName(name)
	if err != nil {
		return err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	var errs []error
	for _, recordType := range []route53types.RRType{route53types.RRTypeA, route53types.RRTypeAaaa} {
		recordSet, err := getRecordSet(ctx, client, hostedZoneID, name, recordType)
		if err != nil {
			errs = append(errs, fmt.Errorf("get route53 %s record %s: %w", recordType, name, err))
			continue
		}
		if recordSet == nil {
			continue
		}
		if err := deleteRecordSet(ctx, client, hostedZoneID, recordSet, "Managed by Portal ENS cleanup"); err != nil {
			errs = append(errs, fmt.Errorf("delete route53 %s record %s: %w", recordType, name, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errRoute53ProviderIsNil
	}
	name, value, err := dnsrecord.TXTInputs(name, value)
	if err != nil {
		return err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureTXTRecord(ctx, client, hostedZoneID, name, value); err != nil {
		return fmt.Errorf("upsert route53 TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errRoute53ProviderIsNil
	}
	name, matchPrefix, err := dnsrecord.TXTPrefixInputs(name, matchPrefix)
	if err != nil {
		return err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteTXTRecords(ctx, client, hostedZoneID, name, matchPrefix); err != nil {
		return fmt.Errorf("delete route53 TXT records %s: %w", name, err)
	}
	return nil
}
