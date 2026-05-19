package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"github.com/gosuda/portal-tunnel/v2/utils"
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
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Content string         `json:"content"`
	Data    *dnsRecordData `json:"data,omitempty"`
}

type dnsRecordData struct {
	Priority int    `json:"priority,omitempty"`
	Target   string `json:"target,omitempty"`
	Value    string `json:"value,omitempty"`
}

type zonesResult struct {
	Errors  []apiError `json:"errors"`
	Result  []zone     `json:"result"`
	Success bool       `json:"success"`
}

type recordsResult struct {
	Errors  []apiError  `json:"errors"`
	Result  []dnsRecord `json:"result"`
	Success bool        `json:"success"`
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
		zones: utils.NewSnapshot(map[string]string{}, utils.CloneMap[string, string]),
	}
}

func (p *Provider) Name() string {
	return "cloudflare"
}

func (p *Provider) ChallengeProvider(context.Context) (challenge.Provider, error) {
	if p == nil {
		return nil, errors.New("cloudflare provider is nil")
	}
	if p.token == "" {
		return nil, errors.New("cloudflare token is required")
	}

	cfg := cloudflare.NewDefaultConfig()
	cfg.AuthToken = p.token

	provider, err := cloudflare.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create cloudflare lego provider: %w", err)
	}
	return provider, nil
}

func (p *Provider) EnsureARecords(ctx context.Context, baseDomain, publicIPv4 string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return errors.New("base domain is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}
	publicIPv4 = strings.TrimSpace(publicIPv4)

	zoneID, err := p.findZoneID(ctx, baseDomain)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	for _, name := range []string{baseDomain, "*." + baseDomain} {
		if err := ensureDNSRecord(ctx, p.token, zoneID, name, "A", publicIPv4); err != nil {
			return fmt.Errorf("ensure A record for %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureARecord(ctx context.Context, name, publicIPv4 string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}
	if err := utils.ValidateIPv4(publicIPv4); err != nil {
		return err
	}
	publicIPv4 = strings.TrimSpace(publicIPv4)

	zoneID, err := p.findZoneID(ctx, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := ensureDNSRecord(ctx, p.token, zoneID, name, "A", publicIPv4); err != nil {
		return fmt.Errorf("ensure A record for %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteARecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}

	zoneID, err := p.findZoneID(ctx, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	records, err := listDNSRecords(ctx, p.token, zoneID, name, "A")
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) {
			continue
		}
		if err := deleteDNSRecord(ctx, p.token, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete A record %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureTXTRecord(ctx context.Context, name, value string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("txt record value is required")
	}

	zoneID, err := p.findZoneID(ctx, name)
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
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}
	matchPrefix = strings.TrimSpace(matchPrefix)
	if matchPrefix == "" {
		return errors.New("txt record match prefix is required")
	}

	zoneID, err := p.findZoneID(ctx, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	records, err := listDNSRecords(ctx, p.token, zoneID, name, "TXT")
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) || !strings.HasPrefix(strings.TrimSpace(record.Content), matchPrefix) {
			continue
		}
		if err := deleteDNSRecord(ctx, p.token, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete TXT record %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureHTTPSRecord(ctx context.Context, name string, priority uint16, target, svcParams, content string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("https record target is required")
	}
	svcParams = strings.TrimSpace(svcParams)
	if svcParams == "" {
		return errors.New("https record svc params are required")
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return errors.New("https record content is required")
	}

	zoneID, err := p.findZoneID(ctx, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := ensureHTTPSRecord(ctx, p.token, zoneID, name, priority, target, svcParams, content); err != nil {
		return fmt.Errorf("ensure HTTPS record for %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteHTTPSRecord(ctx context.Context, name string) error {
	if p == nil {
		return errors.New("cloudflare provider is nil")
	}
	name = utils.NormalizeHostname(name)
	if name == "" {
		return errors.New("record name is required")
	}
	if p.token == "" {
		return errors.New("cloudflare token is required")
	}

	zoneID, err := p.findZoneID(ctx, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	records, err := listDNSRecords(ctx, p.token, zoneID, name, "HTTPS")
	if err != nil {
		return err
	}
	for _, record := range records {
		if !strings.EqualFold(record.Name, name) {
			continue
		}
		if err := deleteDNSRecord(ctx, p.token, zoneID, record.ID); err != nil {
			return fmt.Errorf("delete HTTPS record %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureDNSSEC(ctx context.Context, baseDomain string) (state, dsRecord, message string, err error) {
	if p == nil {
		return "", "", "", errors.New("cloudflare provider is nil")
	}
	baseDomain = utils.NormalizeBaseDomain(baseDomain)
	if baseDomain == "" {
		return "", "", "", errors.New("base domain is required")
	}
	if p.token == "" {
		return "", "", "", errors.New("cloudflare token is required")
	}

	zoneID, err := p.findZoneID(ctx, baseDomain)
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

func (p *Provider) findZoneID(ctx context.Context, domain string) (string, error) {
	domain = utils.NormalizeHostname(domain)
	candidates := utils.DomainCandidates(domain)

	zones := p.zones.Load()
	for _, candidate := range candidates {
		if zoneID := zones[candidate]; zoneID != "" {
			return zoneID, nil
		}
	}

	for _, candidate := range candidates {
		zones, err := listZones(ctx, p.token, candidate)
		if err != nil {
			return "", err
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, candidate) {
				zoneID := strings.TrimSpace(z.ID)
				if zoneID == "" {
					continue
				}
				zoneName := utils.NormalizeHostname(z.Name)
				p.zones.UpdateCopy(func(zones *map[string]string) {
					if *zones == nil {
						*zones = make(map[string]string)
					}
					(*zones)[zoneName] = zoneID
				})
				return zoneID, nil
			}
		}
	}
	return "", fmt.Errorf("no cloudflare zone found for %s", domain)
}

func ensureDNSRecord(ctx context.Context, token, zoneID, name, recordType, content string) error {
	records, err := listDNSRecords(ctx, token, zoneID, name, recordType)
	if err != nil {
		return err
	}

	for _, record := range records {
		if !strings.EqualFold(record.Name, name) {
			continue
		}
		if record.Content == content {
			return nil
		}
		return updateDNSRecord(ctx, token, zoneID, record.ID, recordType, name, content)
	}

	return createDNSRecord(ctx, token, zoneID, recordType, name, content)
}

func ensureTXTRecord(ctx context.Context, token, zoneID, name, value string) error {
	records, err := listDNSRecords(ctx, token, zoneID, name, "TXT")
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

func ensureHTTPSRecord(ctx context.Context, token, zoneID, name string, priority uint16, target, svcParams, content string) error {
	records, err := listDNSRecords(ctx, token, zoneID, name, "HTTPS")
	if err != nil {
		return err
	}

	for _, existing := range records {
		if !strings.EqualFold(existing.Name, name) {
			continue
		}
		if sameHTTPSRecord(existing, priority, target, svcParams, content) {
			return nil
		}
		return updateHTTPSRecord(ctx, token, zoneID, existing.ID, name, priority, target, svcParams, content)
	}

	return createHTTPSRecord(ctx, token, zoneID, name, priority, target, svcParams, content)
}

func sameHTTPSRecord(existing dnsRecord, priority uint16, target, svcParams, content string) bool {
	if existing.Data != nil {
		existingTarget := strings.TrimSpace(existing.Data.Target)
		if existingTarget == "" {
			existingTarget = "."
		}
		return existing.Data.Priority == int(priority) &&
			existingTarget == target &&
			strings.TrimSpace(existing.Data.Value) == svcParams
	}
	return strings.TrimSpace(existing.Content) == content
}

func listZones(ctx context.Context, token, name string) ([]zone, error) {
	u, _ := url.Parse(apiBase + "/zones")
	q := u.Query()
	q.Set("name", name)
	u.RawQuery = q.Encode()

	var out zonesResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodGet, u.String(), nil, cloudflareHeaders(token), &out); err != nil {
		return nil, err
	}
	if !out.Success {
		return nil, wrapErrors(out.Errors)
	}
	return out.Result, nil
}

func listDNSRecords(ctx context.Context, token, zoneID, name, recordType string) ([]dnsRecord, error) {
	u, _ := url.Parse(fmt.Sprintf("%s/zones/%s/dns_records", apiBase, zoneID))
	q := u.Query()
	q.Set("name", name)
	q.Set("type", recordType)
	u.RawQuery = q.Encode()

	var out recordsResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodGet, u.String(), nil, cloudflareHeaders(token), &out); err != nil {
		return nil, err
	}
	if !out.Success {
		return nil, wrapErrors(out.Errors)
	}
	return out.Result, nil
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
	if strings.EqualFold(recordType, "A") {
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

func createHTTPSRecord(ctx context.Context, token, zoneID, name string, priority uint16, target, svcParams, content string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", apiBase, zoneID)
	body := httpsRecordBody("HTTPS", name, priority, target, svcParams, content)

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
	if strings.EqualFold(recordType, "A") {
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

func updateHTTPSRecord(ctx context.Context, token, zoneID, recordID, name string, priority uint16, target, svcParams, content string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", apiBase, zoneID, recordID)
	body := httpsRecordBody("HTTPS", name, priority, target, svcParams, content)

	var out recordResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodPut, endpoint, body, cloudflareHeaders(token), &out); err != nil {
		return err
	}
	if !out.Success {
		return wrapErrors(out.Errors)
	}
	return nil
}

func httpsRecordBody(recordType, name string, priority uint16, target, svcParams, content string) map[string]any {
	return map[string]any{
		"type":    recordType,
		"name":    name,
		"content": content,
		"data": map[string]any{
			"priority": int(priority),
			"target":   target,
			"value":    svcParams,
		},
		"ttl": 1,
	}
}

func deleteDNSRecord(ctx context.Context, token, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", apiBase, zoneID, recordID)

	var out recordResult
	if err := utils.HTTPDoJSON(ctx, nil, http.MethodDelete, endpoint, nil, cloudflareHeaders(token), &out); err != nil {
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
		return errors.New("cloudflare api request failed")
	}
	messages := make([]string, 0, len(errs))
	for _, apiErr := range errs {
		messages = append(messages, fmt.Sprintf("[%d] %s", apiErr.Code, apiErr.Message))
	}
	return errors.New(strings.Join(messages, "; "))
}
