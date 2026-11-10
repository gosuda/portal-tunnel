package route53

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
)

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
