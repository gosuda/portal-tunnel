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
	return &Provider{token: strings.TrimSpace(token)}
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

func (p *Provider) EnsureAddressRecords(ctx context.Context, baseDomain string, publicIPs utils.PublicIPs) error {
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
	publicIPs, err := utils.NormalizePublicIPs(publicIPs)
	if err != nil {
		return err
	}

	zoneID, err := findZoneID(ctx, p.token, baseDomain)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}

	for _, name := range []string{baseDomain, "*." + baseDomain} {
		if err := syncAddressRecords(ctx, p.token, zoneID, name, publicIPs); err != nil {
			return fmt.Errorf("sync A/AAAA record for %s: %w", name, err)
		}
	}
	return nil
}

func (p *Provider) EnsureAddressRecord(ctx context.Context, name string, publicIPs utils.PublicIPs) error {
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
	publicIPs, err := utils.NormalizePublicIPs(publicIPs)
	if err != nil {
		return err
	}

	zoneID, err := findZoneID(ctx, p.token, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := syncAddressRecords(ctx, p.token, zoneID, name, publicIPs); err != nil {
		return fmt.Errorf("sync A/AAAA record for %s: %w", name, err)
	}
	return nil
}

func (p *Provider) DeleteAddressRecord(ctx context.Context, name string) error {
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

	zoneID, err := findZoneID(ctx, p.token, name)
	if err != nil {
		return fmt.Errorf("find cloudflare zone: %w", err)
	}
	if err := deleteManagedDNSRecords(ctx, p.token, zoneID, name, "A", "AAAA"); err != nil {
		return fmt.Errorf("delete A/AAAA record %s: %w", name, err)
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

	zoneID, err := findZoneID(ctx, p.token, name)
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

	zoneID, err := findZoneID(ctx, p.token, name)
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

	zoneID, err := findZoneID(ctx, p.token, baseDomain)
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

func findZoneID(ctx context.Context, token, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	for i := range len(parts) - 1 {
		candidate := strings.Join(parts[i:], ".")
		zones, err := listZones(ctx, token, candidate)
		if err != nil {
			return "", err
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, candidate) {
				return z.ID, nil
			}
		}
	}
	return "", fmt.Errorf("no cloudflare zone found for %s", domain)
}

func syncAddressRecords(ctx context.Context, token, zoneID, name string, publicIPs utils.PublicIPs) error {
	if publicIPs.IPv4 != "" {
		if err := ensureDNSRecord(ctx, token, zoneID, name, "A", publicIPs.IPv4); err != nil {
			return err
		}
	} else if err := deleteManagedDNSRecords(ctx, token, zoneID, name, "A"); err != nil {
		return err
	}

	if publicIPs.IPv6 != "" {
		if err := ensureDNSRecord(ctx, token, zoneID, name, "AAAA", publicIPs.IPv6); err != nil {
			return err
		}
	} else if err := deleteManagedDNSRecords(ctx, token, zoneID, name, "AAAA"); err != nil {
		return err
	}

	return nil
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

func deleteManagedDNSRecords(ctx context.Context, token, zoneID, name string, recordTypes ...string) error {
	for _, recordType := range recordTypes {
		records, err := listDNSRecords(ctx, token, zoneID, name, recordType)
		if err != nil {
			return err
		}
		for _, record := range records {
			if !strings.EqualFold(record.Name, name) {
				continue
			}
			if err := deleteDNSRecord(ctx, token, zoneID, record.ID); err != nil {
				return err
			}
		}
	}
	return nil
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
	if isAddressRecordType(recordType) {
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
	if isAddressRecordType(recordType) {
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

func isAddressRecordType(recordType string) bool {
	return strings.EqualFold(recordType, "A") || strings.EqualFold(recordType, "AAAA")
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
