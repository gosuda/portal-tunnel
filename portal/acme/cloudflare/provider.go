package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"github.com/gosuda/portal-tunnel/v2/portal/acme/internal/dnsrecord"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errCloudflareProviderIsNil    = errors.New("cloudflare provider is nil")
	errCloudflareTokenIsRequired  = errors.New("cloudflare token is required")
	errCloudflareAPIRequestFailed = errors.New("cloudflare api request failed")
)

const (
	apiBase = "https://api.cloudflare.com/client/v4"
)

type Provider struct {
	token string

	zones *utils.Snapshot[map[string]string]
}

type apiError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type zonesResult struct {
	Info    resultInfo `json:"result_info"`
	Errors  []apiError `json:"errors"`
	Result  []zone     `json:"result"`
	Success bool       `json:"success"`
}

type recordsResult struct {
	Info    resultInfo  `json:"result_info"`
	Errors  []apiError  `json:"errors"`
	Result  []dnsRecord `json:"result"`
	Success bool        `json:"success"`
}

type resultInfo struct {
	TotalPages int `json:"total_pages"`
}

type recordResult struct {
	Result  dnsRecord  `json:"result"`
	Errors  []apiError `json:"errors"`
	Success bool       `json:"success"`
}

type dnssecDetails struct {
	DS     string `json:"ds"`
	Status string `json:"status"`
}

type dnssecResult struct {
	Result  dnssecDetails `json:"result"`
	Errors  []apiError    `json:"errors"`
	Success bool          `json:"success"`
}

func New(token string) *Provider {
	return &Provider{
		token: strings.TrimSpace(token),
		zones: utils.NewSnapshot(map[string]string{}, maps.Clone[map[string]string]),
	}
}

func (p *Provider) Name() string {
	return "cloudflare"
}

func (p *Provider) ChallengeProvider(ctx context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errCloudflareProviderIsNil
	}
	if p.token == "" {
		return nil, errCloudflareTokenIsRequired
	}

	cfg := cloudflare.NewDefaultConfig()
	cfg.AuthToken = p.token
	// Keep lego's configuration validation, including its minimum TXT TTL.
	if _, err := cloudflare.NewDNSProviderConfig(cfg); err != nil {
		return nil, fmt.Errorf("create cloudflare lego provider: %w", err)
	}
	return dnsrecord.NewChallengeProvider(ctx, cfg.PropagationTimeout, cfg.PollingInterval,
		func(ctx context.Context, fqdn, value string) (dnsrecord.Cleanup, error) {
			zoneID, err := p.findZoneID(ctx, cfg.HTTPClient, fqdn)
			if err != nil {
				return nil, err
			}
			return presentChallenge(ctx, cfg.HTTPClient, p.token, zoneID, fqdn, value, cfg.TTL)
		}), nil
}

func presentChallenge(ctx context.Context, client *http.Client, token, zoneID, fqdn, value string, ttl int) (dnsrecord.Cleanup, error) {
	name := utils.NormalizeHostname(fqdn)
	existing, err := listDNSRecords(ctx, client, token, zoneID, name, "TXT")
	if err != nil {
		return nil, err
	}
	for _, rec := range existing {
		if strings.EqualFold(rec.Name, name) && strings.EqualFold(rec.Type, "TXT") && dnsrecord.TXTContent(rec.Content) == value {
			return nil, nil
		}
	}
	var recordID string
	cleanup := func(ctx context.Context) error {
		records, err := listDNSRecords(ctx, client, token, zoneID, name, "TXT")
		if err != nil {
			return err
		}
		for _, rec := range records {
			if recordID != "" && rec.ID != recordID {
				continue
			}
			if !strings.EqualFold(rec.Name, name) || !strings.EqualFold(rec.Type, "TXT") || dnsrecord.TXTContent(rec.Content) != value {
				continue
			}
			if err := deleteDNSRecord(ctx, client, token, zoneID, rec.ID); err != nil {
				return err
			}
		}
		return nil
	}
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", apiBase, zoneID)
	body := map[string]any{"type": "TXT", "name": name, "content": `"` + value + `"`, "ttl": ttl}
	var out recordResult
	if err := utils.HTTPDoJSON(ctx, client, http.MethodPost, endpoint, body, cloudflareHeaders(token), &out); err != nil {
		return cleanup, err
	}
	if !out.Success {
		return cleanup, wrapErrors(out.Errors)
	}
	recordID = out.Result.ID
	return cleanup, nil
}

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain, publicIP string) error {
	if p == nil {
		return errCloudflareProviderIsNil
	}
	if p.token == "" {
		return errCloudflareTokenIsRequired
	}
	baseDomain, recordType, publicIP, err := dnsrecord.AddressRecordsInputs(baseDomain, publicIP)
	if err != nil {
		return err
	}

	zoneID, err := p.findZoneID(ctx, nil, baseDomain)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	for _, name := range dnsrecord.ApexWildcard(baseDomain) {
		if err := ensureDNSRecord(ctx, p.token, zoneID, name, recordType, publicIP); err != nil {
			return fmt.Errorf("ensure %s record for %s: %w", recordType, name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name, publicIP string) error {
	if p == nil {
		return errCloudflareProviderIsNil
	}
	if p.token == "" {
		return errCloudflareTokenIsRequired
	}
	name, recordType, publicIP, err := dnsrecord.AddressRecordInputs(name, publicIP)
	if err != nil {
		return err
	}

	zoneID, err := p.findZoneID(ctx, nil, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := ensureDNSRecord(ctx, p.token, zoneID, name, recordType, publicIP); err != nil {
		return fmt.Errorf("ensure %s record for %s: %w", recordType, name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecords(ctx context.Context, name string) error {
	if p == nil {
		return errCloudflareProviderIsNil
	}
	if p.token == "" {
		return errCloudflareTokenIsRequired
	}
	name, err := dnsrecord.RecordName(name)
	if err != nil {
		return err
	}

	zoneID, err := p.findZoneID(ctx, nil, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	var errs []error
	for _, recordType := range []string{"A", "AAAA"} {
		if err := deleteAddressRecordsCloudflare(ctx, p.token, zoneID, name, recordType); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteAddressRecordsCloudflare(ctx context.Context, token, zoneID, name, recordType string) error {
	records, err := listDNSRecords(ctx, nil, token, zoneID, name, recordType)
	if err != nil {
		return fmt.Errorf("list %s records %s: %w", recordType, name, err)
	}
	var errs []error
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) || !strings.EqualFold(record.Type, recordType) {
			continue
		}
		if err := deleteDNSRecord(ctx, nil, token, zoneID, record.ID); err != nil {
			errs = append(errs, fmt.Errorf("delete %s record %s: %w", recordType, name, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errCloudflareProviderIsNil
	}
	if p.token == "" {
		return errCloudflareTokenIsRequired
	}
	name, value, err := dnsrecord.TXTInputs(name, value)
	if err != nil {
		return err
	}

	zoneID, err := p.findZoneID(ctx, nil, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := ensureTXTRecord(ctx, p.token, zoneID, name, value); err != nil {
		return fmt.Errorf("ensure TXT record for %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errCloudflareProviderIsNil
	}
	if p.token == "" {
		return errCloudflareTokenIsRequired
	}
	name, matchPrefix, err := dnsrecord.TXTPrefixInputs(name, matchPrefix)
	if err != nil {
		return err
	}

	zoneID, err := p.findZoneID(ctx, nil, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	records, err := listDNSRecords(ctx, nil, p.token, zoneID, name, "TXT")
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) || !strings.HasPrefix(strings.TrimSpace(record.Content), matchPrefix) {
			continue
		}
		if err := deleteDNSRecord(ctx, nil, p.token, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete TXT record %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errCloudflareProviderIsNil
	}
	if p.token == "" {
		return "", "", "", errCloudflareTokenIsRequired
	}
	baseDomain, err = dnsrecord.BaseDomain(baseDomain)
	if err != nil {
		return "", "", "", err
	}

	zoneID, err := p.findZoneID(ctx, nil, baseDomain)
	if err != nil {
		return "", "", "", fmt.Errorf("find cloudflare zone: %w", err)
	}

	details, err := getDNSSEC(ctx, p.token, zoneID)
	if err != nil {
		return "", "", "", fmt.Errorf("get cloudflare dnssec status: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(details.Status)) {
	case "active", "pending":
	default:
		if err := enableDNSSEC(ctx, p.token, zoneID); err != nil {
			return "", "", "", fmt.Errorf("enable cloudflare dnssec: %w", err)
		}
		details, err = getDNSSEC(ctx, p.token, zoneID)
		if err != nil {
			return "", "", "", fmt.Errorf("refresh cloudflare dnssec status: %w", err)
		}
	}

	state = strings.TrimSpace(details.Status)
	dsRecord = strings.TrimSpace(details.DS)
	if dsRecord != "" {
		message = "publish the DS record at the registrar if Cloudflare Registrar does not manage the zone"
	}
	return state, dsRecord, message, nil
}

func (p *Provider) findZoneID(ctx context.Context, client *http.Client, domain string) (string, error) {
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)
	return searchFindZoneIDCandidates(ctx, p, client, candidates, domain)
}

func searchFindZoneIDCandidates(ctx context.Context, p *Provider, client *http.Client, candidates []string, domain string) (string, error) {
	for _, candidate := range candidates {
		if zoneID := p.zones.Load()[candidate]; zoneID != "" {
			return zoneID, nil
		}
		zoneID, err := fetchFindZoneIDCandidate(ctx, p, client, candidate)
		if err != nil {
			return "", err
		}
		if zoneID != "" {
			return zoneID, nil
		}
	}
	return "", fmt.Errorf("no cloudflare zone found for %s", domain)
}

func fetchFindZoneIDCandidate(ctx context.Context, p *Provider, client *http.Client, candidate string) (string, error) {
	zones, err := listZones(ctx, client, p.token, candidate)
	if err != nil {
		return "", err
	}
	for _, z := range zones {
		if !strings.EqualFold(z.Name, candidate) {
			continue
		}
		zoneID := strings.TrimSpace(z.ID)
		if zoneID == "" {
			continue
		}
		zoneName := utils.NormalizeHostname(z.Name)
		p.zones.UpdateCopy(func(cached *map[string]string) {
			if *cached == nil {
				*cached = make(map[string]string)
			}
			(*cached)[zoneName] = zoneID
		})
		return zoneID, nil
	}
	return "", nil
}

func ensureDNSRecord(ctx context.Context, token, zoneID, name, recordType, content string) error {
	records, err := listDNSRecords(ctx, nil, token, zoneID, name, recordType)
	if err != nil {
		return err
	}

	for _, record := range records {
		if !strings.EqualFold(record.Name, name) || !strings.EqualFold(record.Type, recordType) {
			continue
		}
		if record.Content == content && !record.Proxied {
			return nil
		}
		return updateDNSRecord(ctx, token, zoneID, record.ID, recordType, name, content)
	}

	return createDNSRecord(ctx, token, zoneID, recordType, name, content)
}

func ensureTXTRecord(ctx context.Context, token, zoneID, name, value string) error {
	records, err := listDNSRecords(ctx, nil, token, zoneID, name, "TXT")
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) {
			continue
		}
		if strings.TrimSpace(record.Content) == value {
			return nil
		}
	}
	return createDNSRecord(ctx, token, zoneID, "TXT", name, value)
}

func listZones(ctx context.Context, client *http.Client, token, name string) ([]zone, error) {
	u, _ := url.Parse(apiBase + "/zones")
	q := u.Query()
	q.Set("name", name)
	q.Set("per_page", "100")
	var zones []zone
	for page := 1; ; page++ {
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()
		var out zonesResult
		if err := utils.HTTPDoJSON(ctx, client, http.MethodGet, u.String(), nil, cloudflareHeaders(token), &out); err != nil {
			return nil, err
		}
		if !out.Success {
			return nil, wrapErrors(out.Errors)
		}
		zones = append(zones, out.Result...)
		if page >= out.Info.TotalPages {
			return zones, nil
		}
	}
}

func listDNSRecords(ctx context.Context, client *http.Client, token, zoneID, name, recordType string) ([]dnsRecord, error) {
	u, _ := url.Parse(fmt.Sprintf("%s/zones/%s/dns_records", apiBase, zoneID))
	q := u.Query()
	q.Set("name", name)
	q.Set("type", recordType)
	q.Set("per_page", "100")
	var records []dnsRecord
	for page := 1; ; page++ {
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()
		var out recordsResult
		if err := utils.HTTPDoJSON(ctx, client, http.MethodGet, u.String(), nil, cloudflareHeaders(token), &out); err != nil {
			return nil, err
		}
		if !out.Success {
			return nil, wrapErrors(out.Errors)
		}
		records = append(records, out.Result...)
		if page >= out.Info.TotalPages {
			return records, nil
		}
	}
}

func getDNSSEC(ctx context.Context, token, zoneID string) (dnssecDetails, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dnssec", apiBase, zoneID)

	var out dnssecResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodGet, endpoint, nil, cloudflareHeaders(token), &out); err != nil {
		return dnssecDetails{}, err
	}
	if !out.Success {
		return dnssecDetails{}, wrapErrors(out.Errors)
	}
	return out.Result, nil
}

func enableDNSSEC(ctx context.Context, token, zoneID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dnssec", apiBase, zoneID)
	body := map[string]any{
		"status": "active",
	}

	var out dnssecResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodPatch, endpoint, body, cloudflareHeaders(token), &out); err != nil {
		return err
	}
	if !out.Success {
		return wrapErrors(out.Errors)
	}
	return nil
}

func createDNSRecord(ctx context.Context, token, zoneID, recordType, name, content string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", apiBase, zoneID)
	body := map[string]any{
		"type":    recordType,
		"name":    name,
		"content": content,
		"ttl":     1,
	}
	if strings.EqualFold(recordType, "A") || strings.EqualFold(recordType, "AAAA") {
		body["proxied"] = false
	}

	var out recordResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodPost, endpoint, body, cloudflareHeaders(token), &out); err != nil {
		return err
	}
	if !out.Success {
		return wrapErrors(out.Errors)
	}
	return nil
}

func updateDNSRecord(ctx context.Context, token, zoneID, recordID, recordType, name, content string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", apiBase, zoneID, recordID)
	body := map[string]any{
		"type":    recordType,
		"name":    name,
		"content": content,
		"ttl":     1,
	}
	if strings.EqualFold(recordType, "A") || strings.EqualFold(recordType, "AAAA") {
		body["proxied"] = false
	}

	var out recordResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodPut, endpoint, body, cloudflareHeaders(token), &out); err != nil {
		return err
	}
	if !out.Success {
		return wrapErrors(out.Errors)
	}
	return nil
}

func deleteDNSRecord(ctx context.Context, client *http.Client, token, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", apiBase, zoneID, recordID)

	var out recordResult
	if err := utils.HTTPDoJSON(ctx, client, http.MethodDelete, endpoint, nil, cloudflareHeaders(token), &out); err != nil {
		return err
	}
	if !out.Success {
		return wrapErrors(out.Errors)
	}
	return nil
}

func cloudflareHeaders(token string) http.Header {
	return http.Header{
		"Authorization": []string{"Bearer " + token},
		"Content-Type":  []string{"application/json"},
	}
}

func wrapErrors(errs []apiError) error {
	if len(errs) == 0 {
		return errCloudflareAPIRequestFailed
	}
	messages := make([]string, 0, len(errs))
	for _, apiErr := range errs {
		messages = append(messages, fmt.Sprintf("[%d] %s", apiErr.Code, apiErr.Message))
	}
	return fmt.Errorf("cloudflare api request failed: %s", strings.Join(messages, "; "))
}
