package njalla

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	legonjalla "github.com/go-acme/lego/v4/providers/dns/njalla"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	apiEndpoint      = "https://njal.la/api/1/"
	defaultRecordTTL = 60
)

type Provider struct {
	token string

	client *apiClient
	zones  *utils.Snapshot[map[string]string]
}

type apiClient struct {
	token       string
	apiEndpoint string
	httpClient  *http.Client
}

type apiRequest struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type apiResponse[T any] struct {
	Error  *apiError `json:"error,omitempty"`
	Result T         `json:"result,omitempty"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type dnsRecord struct {
	ID      string `json:"id,omitempty"`
	Content string `json:"content,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Name    string `json:"name,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
	Type    string `json:"type,omitempty"`
}

type recordsResult struct {
	Records []dnsRecord `json:"records,omitempty"`
}

func New(token string) *Provider {
	token = strings.TrimSpace(token)
	return &Provider{
		token:  token,
		client: newAPIClient(token),
		zones:  utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
	}
}

func (p *Provider) Name() string {
	return "njalla"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("njalla provider is nil")
	}
	if p.token == "" {
		return nil, errors.New("njalla token is required")
	}

	cfg := legonjalla.NewDefaultConfig()
	cfg.Token = p.token

	provider, err := legonjalla.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create njalla lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, baseDomain)
	if err != nil {
		return err
	}

	for _, recordName := range []string{baseDomain, "*." + baseDomain} {
		if err := ensureRecord(ctx, client, zone, recordName, "A", strings.TrimSpace(publicIPv4)); err != nil {
			return fmt.Errorf("upsert njalla A record %s: %w", recordName, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, "A", strings.TrimSpace(publicIPv4)); err != nil {
		return fmt.Errorf("upsert njalla A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "A", ""); err != nil {
		return fmt.Errorf("delete njalla A record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureTXTRecord(ctx, client, zone, name, value); err != nil {
		return fmt.Errorf("upsert njalla TXT record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteTXTRecords(ctx context.Context, name, matchPrefix string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "TXT", matchPrefix); err != nil {
		return fmt.Errorf("delete njalla TXT records %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, _ uint16, _, _, content string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("https record content is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := ensureRecord(ctx, client, zone, name, "HTTPS", content); err != nil {
		return fmt.Errorf("upsert njalla HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("njalla provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}

	client, zone, err := p.clientAndZone(ctx, name)
	if err != nil {
		return err
	}
	if err := deleteRecords(ctx, client, zone, name, "HTTPS", ""); err != nil {
		return fmt.Errorf("delete njalla HTTPS record %s: %w", name, err)
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(_ context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("njalla provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
	}
	if p.token == "" {
		return "", "", "", errors.New("njalla token is required")
	}
	return "", "", "", errors.New("njalla provider does not support DNSSEC automation")
}

func (p *Provider) clientAndZone(ctx context.Context, domain string) (*apiClient, string, error) {
	client, err := p.apiClient()
	if err != nil {
		return nil, "", err
	}
	zone, err := p.findZone(ctx, client, domain)
	if err != nil {
		return nil, "", err
	}
	return client, zone, nil
}

func (p *Provider) apiClient() (*apiClient, error) {
	if p == nil {
		return nil, errors.New("njalla provider is nil")
	}
	if p.token == "" {
		return nil, errors.New("njalla token is required")
	}
	if p.client == nil {
		return newAPIClient(p.token), nil
	}
	return p.client, nil
}

func (p *Provider) findZone(ctx context.Context, client *apiClient, domain string) (string, error) {
	if client == nil {
		return "", errors.New("njalla client is nil")
	}
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	for _, candidate := range candidates {
		if zone := zones[candidate]; zone != "" {
			return zone, nil
		}
	}

	var lastErr error
	for _, candidate := range candidates {
		if _, err := client.listRecords(ctx, candidate); err != nil {
			lastErr = err
			continue
		}
		p.zones.UpdateCopy(func(zones *map[string]string) {
			if *zones == nil {
				*zones = make(map[string]string)
			}
			(*zones)[candidate] = candidate
		})
		return candidate, nil
	}

	if lastErr != nil {
		return "", fmt.Errorf("no njalla domain found for %s: %w", domain, lastErr)
	}
	return "", fmt.Errorf("no njalla domain found for %s", domain)
}

func ensureRecord(ctx context.Context, client *apiClient, zone, fqdn, recordType, content string) error {
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return err
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("record content is required")
	}

	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}

	hasDesired := false
	for _, record := range existing {
		if strings.TrimSpace(record.Content) == content && !hasDesired {
			hasDesired = true
			continue
		}
		if err := client.removeRecord(ctx, record.ID, zone); err != nil {
			return err
		}
	}
	if hasDesired {
		return nil
	}

	_, err = client.addRecord(ctx, dnsRecord{
		Content: content,
		Domain:  zone,
		Name:    recordName,
		TTL:     defaultRecordTTL,
		Type:    strings.ToUpper(strings.TrimSpace(recordType)),
	})
	return err
}

func ensureTXTRecord(ctx context.Context, client *apiClient, zone, fqdn, value string) error {
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return err
	}
	existing, err := listRecords(ctx, client, zone, fqdn, "TXT")
	if err != nil {
		return err
	}
	for _, record := range existing {
		if txtContent(record.Content) == value {
			return nil
		}
	}

	_, err = client.addRecord(ctx, dnsRecord{
		Content: value,
		Domain:  zone,
		Name:    recordName,
		TTL:     defaultRecordTTL,
		Type:    "TXT",
	})
	return err
}

func deleteRecords(ctx context.Context, client *apiClient, zone, fqdn, recordType, matchPrefix string) error {
	existing, err := listRecords(ctx, client, zone, fqdn, recordType)
	if err != nil {
		return err
	}
	for _, record := range existing {
		if matchPrefix != "" && !strings.HasPrefix(txtContent(record.Content), matchPrefix) {
			continue
		}
		if err := client.removeRecord(ctx, record.ID, zone); err != nil {
			return err
		}
	}
	return nil
}

func listRecords(ctx context.Context, client *apiClient, zone, fqdn, recordType string) ([]dnsRecord, error) {
	if client == nil {
		return nil, errors.New("njalla client is nil")
	}
	recordName, err := relativeRecordName(fqdn, zone)
	if err != nil {
		return nil, err
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))

	records, err := client.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var filtered []dnsRecord
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Type), recordType) || !sameRecordName(record.Name, recordName, fqdn, zone) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered, nil
}

func relativeRecordName(fqdn, zone string) (string, error) {
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)
	if fqdn == "" {
		return "", errors.New("record name is required")
	}
	if zone == "" {
		return "", errors.New("njalla zone is required")
	}
	if fqdn == zone {
		return "", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("hostname %q is outside njalla zone %q", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

func sameRecordName(recordName, expected, fqdn, zone string) bool {
	recordName = utils.NormalizeHostname(recordName)
	expected = utils.NormalizeHostname(expected)
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)

	if recordName == expected {
		return true
	}
	if expected == "" && (recordName == "" || recordName == "@" || recordName == zone || recordName == fqdn) {
		return true
	}
	return recordName == fqdn
}

func txtContent(raw string) string {
	unquoted, err := strconv.Unquote(strings.TrimSpace(raw))
	if err == nil {
		return unquoted
	}
	return strings.Trim(strings.TrimSpace(raw), "\"")
}

func newAPIClient(token string) *apiClient {
	return &apiClient{
		token:       strings.TrimSpace(token),
		apiEndpoint: apiEndpoint,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *apiClient) addRecord(ctx context.Context, record dnsRecord) (*dnsRecord, error) {
	req := apiRequest{
		Method: "add-record",
		Params: record,
	}

	var result apiResponse[*dnsRecord]
	if err := c.do(ctx, req, &result); err != nil {
		return nil, err
	}
	return result.Result, nil
}

func (c *apiClient) removeRecord(ctx context.Context, id, domain string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("njalla record id is required")
	}

	req := apiRequest{
		Method: "remove-record",
		Params: dnsRecord{
			ID:     id,
			Domain: utils.NormalizeBaseDomain(domain),
		},
	}

	return c.do(ctx, req, &apiResponse[json.RawMessage]{})
}

func (c *apiClient) listRecords(ctx context.Context, domain string) ([]dnsRecord, error) {
	req := apiRequest{
		Method: "list-records",
		Params: dnsRecord{
			Domain: utils.NormalizeBaseDomain(domain),
		},
	}

	var result apiResponse[recordsResult]
	if err := c.do(ctx, req, &result); err != nil {
		return nil, err
	}
	return result.Result.Records, nil
}

func (c *apiClient) do(ctx context.Context, payload apiRequest, result any) error {
	if c == nil {
		return errors.New("njalla client is nil")
	}
	if c.token == "" {
		return errors.New("njalla token is required")
	}

	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(payload); err != nil {
		return fmt.Errorf("encode njalla request: %w", err)
	}

	endpoint := strings.TrimSpace(c.apiEndpoint)
	if endpoint == "" {
		endpoint = apiEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("create njalla request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Njalla "+c.token)

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send njalla request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read njalla response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(raw))
		if detail == "" {
			detail = resp.Status
		}
		return fmt.Errorf("njalla api returned %s: %s", resp.Status, detail)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("decode njalla response: %w", err)
	}

	if response, ok := result.(interface{ apiError() *apiError }); ok {
		if apiErr := response.apiError(); apiErr != nil {
			return apiErr
		}
	}
	return nil
}

func (r *apiResponse[T]) apiError() *apiError {
	if r == nil {
		return nil
	}
	return r.Error
}

func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return fmt.Sprintf("njalla api error %d", e.Code)
	}
	return fmt.Sprintf("njalla api error %d: %s", e.Code, e.Message)
}
