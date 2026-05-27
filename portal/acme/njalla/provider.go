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
	defaultTimeout   = 30 * time.Second
)

type Provider struct {
	token string
	zones *utils.Snapshot[map[string]string]
}

func New(token string) *Provider {
	return &Provider{
		token: strings.TrimSpace(token),
		zones: utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
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
	return "", "", "", errors.New("njalla dnssec automation is not supported; use a DNSSEC-capable provider for ENS gasless automation")
}

func (p *Provider) clientAndZone(ctx context.Context, domain string) (*apiClient, string, error) {
	client, err := p.newClient()
	if err != nil {
		return nil, "", err
	}
	zone, err := p.findZone(ctx, client, domain)
	if err != nil {
		return nil, "", err
	}
	return client, zone, nil
}

func (p *Provider) newClient() (*apiClient, error) {
	if p == nil {
		return nil, errors.New("njalla provider is nil")
	}
	if p.token == "" {
		return nil, errors.New("njalla token is required")
	}
	return &apiClient{
		token:      p.token,
		endpoint:   apiEndpoint,
		httpClient: utils.NewHTTPClient(utils.WithHTTPTimeout(defaultTimeout)),
	}, nil
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
		return "", fmt.Errorf("no njalla zone found for %s: %w", domain, lastErr)
	}
	return "", fmt.Errorf("no njalla zone found for %s", domain)
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
	needsAdd := true
	for _, record := range existing {
		if strings.TrimSpace(record.Content) == content {
			needsAdd = false
			continue
		}
		if err := client.removeRecord(ctx, record.ID.String(), zone); err != nil {
			return err
		}
	}
	if !needsAdd {
		return nil
	}
	_, err = client.addRecord(ctx, record{
		Domain:  zone,
		Name:    recordName,
		Type:    strings.ToUpper(strings.TrimSpace(recordType)),
		TTL:     defaultRecordTTL,
		Content: content,
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
	_, err = client.addRecord(ctx, record{
		Domain:  zone,
		Name:    recordName,
		Type:    "TXT",
		TTL:     defaultRecordTTL,
		Content: value,
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
		if err := client.removeRecord(ctx, record.ID.String(), zone); err != nil {
			return err
		}
	}
	return nil
}

func listRecords(ctx context.Context, client *apiClient, zone, fqdn, recordType string) ([]record, error) {
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
	filtered := make([]record, 0, len(records))
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
		return "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("hostname %q is outside njalla zone %q", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

func sameRecordName(recordName, expected, fqdn, zone string) bool {
	recordName = utils.NormalizeHostname(recordName)
	expected = strings.TrimSpace(strings.ToLower(expected))
	fqdn = utils.NormalizeHostname(fqdn)
	zone = utils.NormalizeBaseDomain(zone)

	if recordName == expected {
		return true
	}
	if expected == "@" && (recordName == "" || recordName == zone || recordName == fqdn) {
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

type apiClient struct {
	token      string
	endpoint   string
	httpClient *http.Client
}

type apiRequest struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

type apiResponse struct {
	Error  *apiError       `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e apiError) Error() string {
	return fmt.Sprintf("code: %d, message: %s", e.Code, e.Message)
}

type recordID string

func (id recordID) String() string {
	return string(id)
}

func (id *recordID) UnmarshalJSON(data []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	switch v := value.(type) {
	case nil:
		*id = ""
	case string:
		*id = recordID(v)
	case json.Number:
		*id = recordID(v.String())
	default:
		return fmt.Errorf("unsupported njalla record id %s", strings.TrimSpace(string(data)))
	}
	return nil
}

type record struct {
	ID      recordID `json:"id,omitempty"`
	Content string   `json:"content,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	Name    string   `json:"name,omitempty"`
	TTL     int      `json:"ttl,omitempty"`
	Type    string   `json:"type,omitempty"`
}

type recordsResult struct {
	Records []record `json:"records,omitempty"`
}

func (c *apiClient) addRecord(ctx context.Context, rec record) (*record, error) {
	var out record
	if err := c.do(ctx, "add-record", rec, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *apiClient) removeRecord(ctx context.Context, id, domain string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("njalla record id is required")
	}
	return c.do(ctx, "remove-record", record{ID: recordID(id), Domain: domain}, nil)
}

func (c *apiClient) listRecords(ctx context.Context, domain string) ([]record, error) {
	var out recordsResult
	if err := c.do(ctx, "list-records", record{Domain: domain}, &out); err != nil {
		return nil, err
	}
	return out.Records, nil
}

func (c *apiClient) do(ctx context.Context, method string, params any, out any) error {
	if c == nil {
		return errors.New("njalla client is nil")
	}
	endpoint := strings.TrimSpace(c.endpoint)
	if endpoint == "" {
		endpoint = apiEndpoint
	}
	body, err := json.Marshal(apiRequest{Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("marshal njalla api request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create njalla api request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Njalla "+c.token)
	req.Header.Set("Content-Type", "application/json")

	client := c.httpClient
	if client == nil {
		client = utils.DefaultHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read njalla api response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("njalla api %s failed: %s", method, resp.Status)
	}

	var envelope apiResponse
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode njalla api response: %w", err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if out == nil || len(envelope.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return fmt.Errorf("decode njalla api result: %w", err)
	}
	return nil
}
