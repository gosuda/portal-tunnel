package route53

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"github.com/cenkalti/backoff/v5"
	"github.com/go-acme/lego/v4/platform/wait"
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
				// Retain lego's Route53 throttling backoff and retry limit.
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
	// Join the outer SDK credential cache refresh instead of abandoning it on
	// cancellation. Nested caches may finish separately; their network operations
	// still use ctx above. The SDK loader does not expose a process
	// command builder, so credential_process keeps its timeout, capped above to
	// the remaining budget at client creation rather than prompt cancellation.
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
		// Rebuild the credential chain so no canceled issuance context is retained.
		client, err := newChallengeClient(ctx, cfg)
		if err != nil {
			return err
		}
		return cleanupChallenge(ctx, client, cfg, zone, name, value)
	}
	// A failed request may already have changed DNS. Retain exact cleanup even
	// when the write or its acknowledgement has an uncertain outcome.
	return cleanup, changeChallengeRecord(ctx, client, cfg, cfg.WaitForRecordSetsChanged, zone, route53types.ChangeActionUpsert, recordSet)
}

func cleanupChallenge(ctx context.Context, client *awsroute53.Client, cfg *route53.Config, zone, name, value string) error {
	// An accepted write is enough for cleanup. Waiting for INSYNC can
	// spend the entire order's shared budget before the next TXT removal.
	// Route53 may reject a new same-zone change while processing the prior
	// one. Re-read before retrying so unrelated values are preserved.
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
