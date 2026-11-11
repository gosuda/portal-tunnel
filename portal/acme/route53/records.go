package route53

import (
	"context"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
