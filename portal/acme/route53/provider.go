package route53

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/cenkalti/backoff/v5"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/platform/wait"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"

	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
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

// Credential caches in the AWS SDK suppress caller cancellation. Restore it at
// each SDK operation, including the STS, SSO, ECS and IMDS credential clients,
// while retaining the SDK's operation-specific context values.
type challengeContext struct {
	context.Context
	values context.Context
}

func (c challengeContext) Value(key any) any { return c.values.Value(key) }

func newChallengeClient(ctx context.Context, cfg *route53.Config) (*awsroute53.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	options := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
		config.WithProcessCredentialOptions(func(options *processcreds.Options) {
			if deadline, ok := ctx.Deadline(); ok {
				options.Timeout = min(options.Timeout, max(time.Until(deadline), time.Nanosecond))
			}
		}),
		config.WithAPIOptions([]func(*middleware.Stack) error{
			func(stack *middleware.Stack) error {
				return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("PortalChallengeContext",
					func(values context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
						return next.HandleInitialize(challengeContext{Context: ctx, values: values}, in)
					}), middleware.Before)
			},
		}),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = cfg.MaxRetries

				options.Backoff = retry.BackoffDelayerFunc(func(attempt int, _ error) (time.Duration, error) {
					delay := (1 << uint(min(attempt, 7))) * (rand.IntN(50) + 200)
					return time.Duration(delay) * time.Millisecond, nil
				})
			})
		}),
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		options = append(options, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load aws challenge config: %w", err)
	}

	credentialSource := awsCfg.Credentials
	awsCfg.Credentials = aws.CredentialsProviderFunc(func(callCtx context.Context) (aws.Credentials, error) {
		if err := ctx.Err(); err != nil {
			return aws.Credentials{}, err
		}
		return credentialSource.Retrieve(context.WithoutCancel(callCtx))
	})
	if cfg.AssumeRoleArn != "" {
		awsCfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), cfg.AssumeRoleArn,
			func(options *stscreds.AssumeRoleOptions) {
				if cfg.ExternalID != "" {
					options.ExternalID = aws.String(cfg.ExternalID)
				}
			})
	}
	return awsroute53.NewFromConfig(awsCfg), nil
}

func challengeHostedZone(ctx context.Context, client *awsroute53.Client, cfg *route53.Config, name string) (string, error) {
	if cfg.HostedZoneID != "" {
		return normalizeZoneID(cfg.HostedZoneID), nil
	}
	for _, candidate := range utils.DomainCandidates(name) {
		input := &awsroute53.ListHostedZonesByNameInput{DNSName: aws.String(candidate)}
		for {
			out, err := client.ListHostedZonesByName(ctx, input)
			if err != nil {
				return "", fmt.Errorf("list route53 hosted zones: %w", err)
			}
			for _, zone := range out.HostedZones {
				private := zone.Config != nil && zone.Config.PrivateZone
				if utils.NormalizeHostname(aws.ToString(zone.Name)) == candidate && private == cfg.PrivateZone {
					return normalizeZoneID(aws.ToString(zone.Id)), nil
				}
			}
			if !out.IsTruncated || utils.NormalizeHostname(aws.ToString(out.NextDNSName)) != candidate {
				break
			}
			input.DNSName, input.HostedZoneId = out.NextDNSName, out.NextHostedZoneId
		}
	}
	return "", fmt.Errorf("no route53 hosted zone found for %s (private=%t)", name, cfg.PrivateZone)
}

func presentChallenge(ctx context.Context, cfg *route53.Config, name, value string) (dnsrecord.Cleanup, error) {
	client, err := newChallengeClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	zone, err := challengeHostedZone(ctx, client, cfg, name)
	if err != nil {
		return nil, err
	}
	recordSet, err := getTXTRecordSet(ctx, client, zone, name)
	if err != nil {
		return nil, err
	}
	if recordSet == nil {
		recordSet = &route53types.ResourceRecordSet{
			Name: aws.String(name), Type: route53types.RRTypeTxt, TTL: aws.Int64(int64(cfg.TTL)),
		}
	}
	for _, record := range recordSet.ResourceRecords {
		if dnsrecord.TXTContent(aws.ToString(record.Value)) == value {
			return nil, nil
		}
	}
	recordSet.ResourceRecords = append(recordSet.ResourceRecords, route53types.ResourceRecord{Value: aws.String(route53TXTValue(value))})
	cleanup := func(ctx context.Context) error {

		client, err := newChallengeClient(ctx, cfg)
		if err != nil {
			return err
		}
		return cleanupChallenge(ctx, client, cfg, zone, name, value)
	}

	return cleanup, changeChallengeRecord(ctx, client, cfg, cfg.WaitForRecordSetsChanged, zone, route53types.ChangeActionUpsert, recordSet)
}

func cleanupChallenge(ctx context.Context, client *awsroute53.Client, cfg *route53.Config, zone, name, value string) error {

	return wait.Retry(ctx, func() error {
		recordSet, err := getTXTRecordSet(ctx, client, zone, name)
		if err != nil || recordSet == nil {
			return backoff.Permanent(err)
		}
		remaining := make([]route53types.ResourceRecord, 0, len(recordSet.ResourceRecords))
		for _, record := range recordSet.ResourceRecords {
			if dnsrecord.TXTContent(aws.ToString(record.Value)) != value {
				remaining = append(remaining, record)
			}
		}
		if len(remaining) == len(recordSet.ResourceRecords) {
			return nil
		}
		action := route53types.ChangeActionDelete
		if len(remaining) > 0 {
			action = route53types.ChangeActionUpsert
			recordSet.ResourceRecords = remaining
		}
		err = changeChallengeRecord(ctx, client, cfg, false, zone, action, recordSet)
		var prior *route53types.PriorRequestNotComplete
		if errors.As(err, &prior) {
			return err
		}
		return backoff.Permanent(err)
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
}

func changeChallengeRecord(ctx context.Context, client *awsroute53.Client, cfg *route53.Config, waitForPropagation bool, zone string, action route53types.ChangeAction, recordSet *route53types.ResourceRecordSet) error {
	out, err := client.ChangeResourceRecordSets(ctx, &awsroute53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone),
		ChangeBatch: &route53types.ChangeBatch{
			Comment: aws.String("Managed by Portal ACME"),
			Changes: []route53types.Change{{Action: action, ResourceRecordSet: recordSet}},
		},
	})
	if err != nil || !waitForPropagation {
		return err
	}
	return wait.Retry(ctx, func() error {
		change, err := client.GetChange(ctx, &awsroute53.GetChangeInput{Id: out.ChangeInfo.Id})
		if err != nil {
			return err
		}
		if change.ChangeInfo.Status != route53types.ChangeStatusInsync {
			return fmt.Errorf("route53 change %s is %s", aws.ToString(out.ChangeInfo.Id), change.ChangeInfo.Status)
		}
		return nil
	}, backoff.WithBackOff(backoff.NewConstantBackOff(cfg.PollingInterval)), backoff.WithMaxElapsedTime(cfg.PropagationTimeout))
}
func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errRoute53ProviderIsNil
	}
	baseDomain, err = dnsrecord.BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}

	client, hostedZoneID, err := p.clientAndZone(ctx, baseDomain)
	if err != nil {
		return "", "", "", err
	}

	return signEnsureDNSSECZone(ctx, client, hostedZoneID, p.cfg)
}

func getDNSSECStatus(ctx context.Context, client *awsroute53.Client, hostedZoneID string) (*awsroute53.GetDNSSECOutput, error) {
	if client == nil {
		return nil, errRoute53ClientIsNil
	}
	if hostedZoneID == "" {
		return nil, errHostedZoneIDIsRequired
	}
	return client.GetDNSSEC(ctx, &awsroute53.GetDNSSECInput{
		HostedZoneId: aws.String(hostedZoneID),
	})
}

func ensureActiveKeySigningKey(ctx context.Context, client *awsroute53.Client, hostedZoneID string, cfg Config, keys []route53types.KeySigningKey) error {
	if client == nil {
		return errRoute53ClientIsNil
	}
	kskName := defaultDNSSECKSKName

	if existing, ok := keySigningKeyByName(keys, kskName); ok {
		return activateExistingSigningKey(ctx, client, hostedZoneID, kskName, existing)
	}

	if strings.TrimSpace(cfg.KMSKeyARN) == "" {
		return errRoute53DnssecRequiresAwsDnssecKms
	}

	_, err := client.CreateKeySigningKey(ctx, &awsroute53.CreateKeySigningKeyInput{
		CallerReference:         aws.String(fmt.Sprintf("portal-%d", time.Now().UTC().UnixNano())),
		HostedZoneId:            aws.String(hostedZoneID),
		KeyManagementServiceArn: aws.String(cfg.KMSKeyARN),
		Name:                    aws.String(kskName),
		Status:                  aws.String("ACTIVE"),
	})
	if err != nil {
		if _, ok := errors.AsType[*route53types.KeySigningKeyAlreadyExists](err); ok {
			return nil
		}
		return fmt.Errorf("create route53 key-signing key %q: %w", kskName, err)
	}
	return nil
}

func dnssecStatusFromOutput(out *awsroute53.GetDNSSECOutput) (state, dsRecord, message string) {
	if out == nil {
		return "", "", ""
	}

	if out.Status != nil {
		state = strings.TrimSpace(aws.ToString(out.Status.ServeSignature))
		message = strings.TrimSpace(aws.ToString(out.Status.StatusMessage))
	}
	if active, ok := activeKeySigningKey(out.KeySigningKeys); ok {
		dsRecord = strings.TrimSpace(aws.ToString(active.DSRecord))
	} else {
		for _, key := range out.KeySigningKeys {
			if strings.TrimSpace(aws.ToString(key.DSRecord)) != "" {
				dsRecord = strings.TrimSpace(aws.ToString(key.DSRecord))
				break
			}
		}
	}
	if message == "" && dsRecord != "" {
		message = "publish the DS record at the registrar after Route53 zone signing is enabled"
	}
	return state, dsRecord, message
}

func activeKeySigningKey(keys []route53types.KeySigningKey) (route53types.KeySigningKey, bool) {
	for _, key := range keys {
		if strings.EqualFold(strings.TrimSpace(aws.ToString(key.Status)), "ACTIVE") {
			return key, true
		}
	}
	return route53types.KeySigningKey{}, false
}

func keySigningKeyByName(keys []route53types.KeySigningKey, name string) (route53types.KeySigningKey, bool) {
	for _, key := range keys {
		if strings.EqualFold(strings.TrimSpace(aws.ToString(key.Name)), name) {
			return key, true
		}
	}
	return route53types.KeySigningKey{}, false
}

func ensureDNSSECActiveKey(ctx context.Context, client *awsroute53.Client, hostedZoneID string, cfg Config, out *awsroute53.GetDNSSECOutput) (*awsroute53.GetDNSSECOutput, error) {
	if _, ok := activeKeySigningKey(out.KeySigningKeys); ok {
		return out, nil
	}
	if err := ensureActiveKeySigningKey(ctx, client, hostedZoneID, cfg, out.KeySigningKeys); err != nil {
		return nil, err
	}
	out, err := getDNSSECStatus(ctx, client, hostedZoneID)
	if err != nil {
		return nil, fmt.Errorf("refresh route53 dnssec status: %w", err)
	}
	if _, ok := activeKeySigningKey(out.KeySigningKeys); !ok {
		return nil, errRoute53DnssecRequiresActiveKeySigning
	}
	return out, nil
}

func enableEnsureDNSSECZoneSigning(ctx context.Context, client *awsroute53.Client, hostedZoneID string) (*awsroute53.GetDNSSECOutput, error) {
	if _, err := client.EnableHostedZoneDNSSEC(ctx, &awsroute53.EnableHostedZoneDNSSECInput{
		HostedZoneId: aws.String(hostedZoneID),
	}); err != nil {
		return nil, fmt.Errorf("enable route53 dnssec: %w", err)
	}
	out, err := getDNSSECStatus(ctx, client, hostedZoneID)
	if err != nil {
		return nil, fmt.Errorf("refresh route53 dnssec status: %w", err)
	}
	return out, nil
}

func signEnsureDNSSECZone(ctx context.Context, client *awsroute53.Client, hostedZoneID string, cfg Config) (string, string, string, error) {
	out, err := getDNSSECStatus(ctx, client, hostedZoneID)
	if err != nil {
		return "", "", "", fmt.Errorf("get route53 dnssec status: %w", err)
	}
	if state, dsRecord, message := dnssecStatusFromOutput(out); strings.EqualFold(state, "SIGNING") {
		return state, dsRecord, message, nil
	}
	_, err = ensureDNSSECActiveKey(ctx, client, hostedZoneID, cfg, out)
	if err != nil {
		return "", "", "", err
	}
	out, err = enableEnsureDNSSECZoneSigning(ctx, client, hostedZoneID)
	if err != nil {
		return "", "", "", err
	}
	state, dsRecord, message := dnssecStatusFromOutput(out)
	return state, dsRecord, message, nil
}

func activateExistingSigningKey(ctx context.Context, client *awsroute53.Client, hostedZoneID, kskName string, existing route53types.KeySigningKey) error {
	if strings.EqualFold(strings.TrimSpace(aws.ToString(existing.Status)), "ACTIVE") {
		return nil
	}
	if _, err := client.ActivateKeySigningKey(ctx, &awsroute53.ActivateKeySigningKeyInput{
		HostedZoneId: aws.String(hostedZoneID),
		Name:         aws.String(kskName),
	}); err != nil {
		return fmt.Errorf("activate route53 key-signing key %q: %w", kskName, err)
	}
	return nil
}
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
func upsertTXTRecord(ctx context.Context, client *awsroute53.Client, hostedZoneID, name, value string) error {
	return upsertRecord(ctx, client, hostedZoneID, name, route53types.RRTypeTxt, []string{route53TXTValue(value)}, "Managed by Portal ENS")
}

func ensureTXTRecord(ctx context.Context, client *awsroute53.Client, hostedZoneID, name, value string) error {
	recordSet, err := getTXTRecordSet(ctx, client, hostedZoneID, name)
	if err != nil {
		return err
	}
	if recordSet == nil {
		return upsertTXTRecord(ctx, client, hostedZoneID, name, value)
	}

	for _, record := range recordSet.ResourceRecords {
		if dnsrecord.TXTContent(aws.ToString(record.Value)) == value {
			return nil
		}
	}

	values := make([]string, 0, len(recordSet.ResourceRecords)+1)
	for _, record := range recordSet.ResourceRecords {
		values = append(values, aws.ToString(record.Value))
	}
	values = append(values, route53TXTValue(value))
	return upsertRecord(ctx, client, hostedZoneID, name, route53types.RRTypeTxt, values, "Managed by Portal ENS")
}

func deleteTXTRecords(ctx context.Context, client *awsroute53.Client, hostedZoneID, name, matchPrefix string) error {
	recordSet, err := getTXTRecordSet(ctx, client, hostedZoneID, name)
	if err != nil {
		return err
	}
	if recordSet == nil {
		return nil
	}

	remaining := make([]string, 0, len(recordSet.ResourceRecords))
	removed := false
	for _, record := range recordSet.ResourceRecords {
		value := aws.ToString(record.Value)
		if strings.HasPrefix(dnsrecord.TXTContent(value), matchPrefix) {
			removed = true
			continue
		}
		remaining = append(remaining, value)
	}
	if !removed {
		return nil
	}
	if len(remaining) == 0 {
		return deleteRecordSet(ctx, client, hostedZoneID, recordSet, "Managed by Portal ENS cleanup")
	}
	return upsertRecord(ctx, client, hostedZoneID, name, route53types.RRTypeTxt, remaining, "Managed by Portal ENS cleanup")
}

func upsertRecord(ctx context.Context, client *awsroute53.Client, hostedZoneID, name string, recordType route53types.RRType, values []string, comment string) error {
	if client == nil {
		return errRoute53ClientIsNil
	}
	if hostedZoneID == "" {
		return errHostedZoneIDIsRequired
	}

	fqdn := utils.NormalizeHostname(name)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	recordSet := &route53types.ResourceRecordSet{
		Name:            aws.String(fqdn),
		Type:            recordType,
		TTL:             aws.Int64(60),
		ResourceRecords: make([]route53types.ResourceRecord, 0, len(values)),
	}
	for _, value := range values {
		recordSet.ResourceRecords = append(recordSet.ResourceRecords, route53types.ResourceRecord{
			Value: aws.String(strings.TrimSpace(value)),
		})
	}

	_, err := client.ChangeResourceRecordSets(ctx, &awsroute53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53types.ChangeBatch{
			Comment: aws.String(comment),
			Changes: []route53types.Change{
				{
					Action:            route53types.ChangeActionUpsert,
					ResourceRecordSet: recordSet,
				},
			},
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func route53TXTValue(value string) string {
	return strconv.Quote(strings.TrimSpace(value))
}

func getTXTRecordSet(ctx context.Context, client *awsroute53.Client, hostedZoneID, name string) (*route53types.ResourceRecordSet, error) {
	return getRecordSet(ctx, client, hostedZoneID, name, route53types.RRTypeTxt)
}

func getRecordSet(ctx context.Context, client *awsroute53.Client, hostedZoneID, name string, recordType route53types.RRType) (*route53types.ResourceRecordSet, error) {
	if client == nil {
		return nil, errRoute53ClientIsNil
	}
	fqdn := utils.NormalizeHostname(name)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	out, err := client.ListResourceRecordSets(ctx, &awsroute53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(hostedZoneID),
		StartRecordName: aws.String(fqdn),
		StartRecordType: recordType,
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	if len(out.ResourceRecordSets) == 0 {
		return nil, nil
	}
	recordSet := out.ResourceRecordSets[0]
	if !strings.EqualFold(strings.TrimSpace(aws.ToString(recordSet.Name)), fqdn) || recordSet.Type != recordType {
		return nil, nil
	}
	return &recordSet, nil
}

func deleteRecordSet(ctx context.Context, client *awsroute53.Client, hostedZoneID string, recordSet *route53types.ResourceRecordSet, comment string) error {
	if client == nil {
		return errRoute53ClientIsNil
	}
	if recordSet == nil {
		return nil
	}
	_, err := client.ChangeResourceRecordSets(ctx, &awsroute53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &route53types.ChangeBatch{
			Comment: aws.String(comment),
			Changes: []route53types.Change{
				{
					Action:            route53types.ChangeActionDelete,
					ResourceRecordSet: recordSet,
				},
			},
		},
	})
	return err
}
