package route53

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/gosuda/portal-tunnel/v2/utils"
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
	cfg    Config
	zoneMu sync.RWMutex
	zones  map[string]string
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
	}
}

func (p *Provider) Name() string {
	return "route53"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("route53 provider is nil")
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

	provider, err := route53.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create route53 lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range []string{baseDomain, "*." + baseDomain} {
		if err := upsertARecord(ctx, client, hostedZoneID, recordName, publicIPv4); err != nil {
			return fmt.Errorf("upsert route53 A record %s: %w", recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return err
	}
	if err := upsertARecord(ctx, client, hostedZoneID, name, publicIPv4); err != nil {
		return fmt.Errorf("upsert route53 A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return err
	}
	recordSet, err := getRecordSet(ctx, client, hostedZoneID, name, route53types.RRTypeA)
	if err != nil {
		return err
	}
	if recordSet == nil {
		return nil
	}
	if err := deleteRecordSet(ctx, client, hostedZoneID, recordSet, "Managed by Portal ENS cleanup"); err != nil {
		return fmt.Errorf("delete route53 A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
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
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return err
	}
	if err := deleteTXTRecords(ctx, client, hostedZoneID, name, matchPrefix); err != nil {
		return fmt.Errorf("delete route53 TXT records %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, _ uint16, _, _, content string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("https record content is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return err
	}
	if err := upsertRecord(ctx, client, hostedZoneID, name, route53types.RRTypeHttps, []string{content}, "Managed by Portal ECH"); err != nil {
		return fmt.Errorf("upsert route53 HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("route53 provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, name)
	if err != nil {
		return err
	}
	recordSet, err := getRecordSet(ctx, client, hostedZoneID, name, route53types.RRTypeHttps)
	if err != nil {
		return err
	}
	if recordSet == nil {
		return nil
	}
	if err := deleteRecordSet(ctx, client, hostedZoneID, recordSet, "Managed by Portal ECH cleanup"); err != nil {
		return fmt.Errorf("delete route53 HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("route53 provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
	}

	client, err := newClient(ctx, p.cfg)
	if err != nil {
		return "", "", "", err
	}

	hostedZoneID, err := p.findHostedZoneID(ctx, client, baseDomain)
	if err != nil {
		return "", "", "", err
	}

	out, err := getDNSSECStatus(ctx, client, hostedZoneID)
	if err != nil {
		return "", "", "", fmt.Errorf("get route53 dnssec status: %w", err)
	}
	state, dsRecord, message = dnssecStatusFromOutput(out)
	if strings.EqualFold(state, "SIGNING") {
		return state, dsRecord, message, nil
	}

	if _, ok := activeKeySigningKey(out.KeySigningKeys); !ok {
		if err := ensureActiveKeySigningKey(ctx, client, hostedZoneID, p.cfg, out.KeySigningKeys); err != nil {
			return "", "", "", err
		}
		out, err = getDNSSECStatus(ctx, client, hostedZoneID)
		if err != nil {
			return "", "", "", fmt.Errorf("refresh route53 dnssec status: %w", err)
		}
		if _, ok := activeKeySigningKey(out.KeySigningKeys); !ok {
			return "", "", "", errors.New("route53 dnssec requires an ACTIVE key-signing key")
		}
	}

	if _, err := client.EnableHostedZoneDNSSEC(ctx, &awsroute53.EnableHostedZoneDNSSECInput{
		HostedZoneId: aws.String(hostedZoneID),
	}); err != nil {
		return "", "", "", fmt.Errorf("enable route53 dnssec: %w", err)
	}

	out, err = getDNSSECStatus(ctx, client, hostedZoneID)
	if err != nil {
		return "", "", "", fmt.Errorf("refresh route53 dnssec status: %w", err)
	}
	state, dsRecord, message = dnssecStatusFromOutput(out)
	return state, dsRecord, message, nil
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

func (p *Provider) findHostedZoneID(ctx context.Context, client *awsroute53.Client, domain string) (string, error) {
	if explicitZoneID := normalizeZoneID(p.cfg.HostedZoneID); explicitZoneID != "" {
		return explicitZoneID, nil
	}
	if client == nil {
		return "", errors.New("route53 client is nil")
	}

	candidates := utils.DomainCandidates(domain)
	if len(candidates) == 0 {
		return "", fmt.Errorf("invalid base domain for hosted zone lookup: %q", domain)
	}

	p.zoneMu.RLock()
	for _, candidate := range candidates {
		if zoneID := p.zones[candidate]; zoneID != "" {
			p.zoneMu.RUnlock()
			return zoneID, nil
		}
	}
	p.zoneMu.RUnlock()

	zonesByName := make(map[string]string)
	paginator := awsroute53.NewListHostedZonesPaginator(client, &awsroute53.ListHostedZonesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("list hosted zones: %w", err)
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

	if len(zonesByName) > 0 {
		p.zoneMu.Lock()
		if p.zones == nil {
			p.zones = make(map[string]string)
		}
		for zoneName, zoneID := range zonesByName {
			p.zones[zoneName] = zoneID
		}
		p.zoneMu.Unlock()
	}

	for _, candidate := range candidates {
		if zoneID, ok := zonesByName[candidate]; ok {
			return zoneID, nil
		}
	}

	return "", fmt.Errorf("no route53 public hosted zone found for %s", domain)
}

func upsertARecord(ctx context.Context, client *awsroute53.Client, hostedZoneID, name, ip string) error {
	return upsertRecord(ctx, client, hostedZoneID, name, route53types.RRTypeA, []string{strings.TrimSpace(ip)}, "Managed by Portal ACME")
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
		if route53TXTContent(aws.ToString(record.Value)) == value {
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
		if strings.HasPrefix(route53TXTContent(value), matchPrefix) {
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
		return errors.New("route53 client is nil")
	}
	if hostedZoneID == "" {
		return errors.New("hosted zone id is required")
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

func route53TXTContent(value string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(value))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(value), "\"")
}

func getTXTRecordSet(ctx context.Context, client *awsroute53.Client, hostedZoneID, name string) (*route53types.ResourceRecordSet, error) {
	return getRecordSet(ctx, client, hostedZoneID, name, route53types.RRTypeTxt)
}

func getRecordSet(ctx context.Context, client *awsroute53.Client, hostedZoneID, name string, recordType route53types.RRType) (*route53types.ResourceRecordSet, error) {
	if client == nil {
		return nil, errors.New("route53 client is nil")
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
		return errors.New("route53 client is nil")
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
		return errors.New("route53 session token requires access key id and secret access key")
	case (cfg.AccessKeyID == "") != (cfg.SecretAccessKey == ""):
		return errors.New("route53 access key id and secret access key must be supplied together")
	}
	return nil
}

func normalizeZoneID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	return strings.TrimPrefix(trimmed, "/hostedzone/")
}

func getDNSSECStatus(ctx context.Context, client *awsroute53.Client, hostedZoneID string) (*awsroute53.GetDNSSECOutput, error) {
	if client == nil {
		return nil, errors.New("route53 client is nil")
	}
	if hostedZoneID == "" {
		return nil, errors.New("hosted zone id is required")
	}
	return client.GetDNSSEC(ctx, &awsroute53.GetDNSSECInput{
		HostedZoneId: aws.String(hostedZoneID),
	})
}

func ensureActiveKeySigningKey(ctx context.Context, client *awsroute53.Client, hostedZoneID string, cfg Config, keys []route53types.KeySigningKey) error {
	if client == nil {
		return errors.New("route53 client is nil")
	}
	kskName := defaultDNSSECKSKName

	if existing, ok := keySigningKeyByName(keys, kskName); ok {
		if strings.EqualFold(strings.TrimSpace(aws.ToString(existing.Status)), "ACTIVE") {
			return nil
		}
		_, err := client.ActivateKeySigningKey(ctx, &awsroute53.ActivateKeySigningKeyInput{
			HostedZoneId: aws.String(hostedZoneID),
			Name:         aws.String(kskName),
		})
		if err != nil {
			return fmt.Errorf("activate route53 key-signing key %q: %w", kskName, err)
		}
		return nil
	}

	if strings.TrimSpace(cfg.KMSKeyARN) == "" {
		return errors.New("route53 dnssec requires AWS_DNSSEC_KMS_KEY_ARN when no active key-signing key exists")
	}

	_, err := client.CreateKeySigningKey(ctx, &awsroute53.CreateKeySigningKeyInput{
		CallerReference:         aws.String(fmt.Sprintf("portal-%d", time.Now().UTC().UnixNano())),
		HostedZoneId:            aws.String(hostedZoneID),
		KeyManagementServiceArn: aws.String(cfg.KMSKeyARN),
		Name:                    aws.String(kskName),
		Status:                  aws.String("ACTIVE"),
	})
	if err != nil {
		var alreadyExists *route53types.KeySigningKeyAlreadyExists
		if errors.As(err, &alreadyExists) {
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
