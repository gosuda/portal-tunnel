package njalla

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

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
		return errNjallaRecordIDIsRequired
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
		return errNjallaClientIsNil
	}
	req, err := buildRequestNjalla(ctx, c, method, params)
	if err != nil {
		return err
	}
	return c.roundTripNjalla(req, method, out)
}

func buildRequestNjalla(ctx context.Context, c *apiClient, method string, params any) (*http.Request, error) {
	endpoint := strings.TrimSpace(c.endpoint)
	endpoint = cmp.Or(endpoint, apiEndpoint)
	body, err := json.Marshal(apiRequest{Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("marshal njalla api request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create njalla api request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Njalla "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *apiClient) roundTripNjalla(req *http.Request, method string, out any) error {
	client := c.httpClient
	if client == nil {
		client = utils.DefaultHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponseNjalla(resp, method, out)
}

func decodeResponseNjalla(resp *http.Response, method string, out any) error {
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

func pruneRecordsNjalla(ctx context.Context, client *apiClient, zone string, existing []record, content string) (bool, error) {
	needsAdd := true
	for _, record := range existing {
		if strings.TrimSpace(record.Content) == content {
			needsAdd = false
			continue
		}
		if err := client.removeRecord(ctx, record.ID.String(), zone); err != nil {
			return false, err
		}
	}
	return needsAdd, nil
}

func (c *apiClient) insertRecordNjalla(ctx context.Context, zone, recordName, recordType, content string) error {
	if _, err := c.addRecord(ctx, record{
		Domain:  zone,
		Name:    recordName,
		Type:    strings.ToUpper(strings.TrimSpace(recordType)),
		TTL:     defaultRecordTTL,
		Content: content,
	}); err != nil {
		return err
	}
	return nil
}
