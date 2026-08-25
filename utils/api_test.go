package utils

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestWriteAPIDataAndDecodeEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	WriteAPIData(rec, http.StatusCreated, map[string]string{"status": "ok"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("WriteAPIData() status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var envelope types.APIEnvelope[map[string]string]
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	if !envelope.OK || envelope.Data["status"] != "ok" {
		t.Fatalf("decoded envelope = %+v, want ok envelope", envelope)
	}
}

func TestDecodeAPIRequestError(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       io.NopCloser(strings.NewReader(`{"ok":false,"error":{"code":"unauthorized","message":"denied"}}`)),
	}

	err := DecodeAPIRequestError(resp)
	var apiErr *types.APIRequestError
	if !errors.As(err, &apiErr) {
		t.Fatalf("DecodeAPIRequestError() error = %T, want *types.APIRequestError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "unauthorized" || apiErr.Message != "denied" {
		t.Fatalf("DecodeAPIRequestError() = %+v, want status/code/message populated", apiErr)
	}
}

func TestDecodeJSONRequestWritesInvalidJSONError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	if _, ok := DecodeJSONRequest[map[string]string](rec, req, 1024); ok {
		t.Fatal("DecodeJSONRequest() ok = true, want false")
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("DecodeJSONRequest() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var envelope types.APIEnvelope[json.RawMessage]
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != types.APIErrorCodeInvalidJSON {
		t.Fatalf("decoded envelope = %+v, want invalid_json error", envelope)
	}
}

func TestDecodeJSONRequestRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{"value":"too large"}`))
	rec := httptest.NewRecorder()

	if _, ok := DecodeJSONRequest[map[string]string](rec, req, 8); ok {
		t.Fatal("DecodeJSONRequest() ok = true, want false")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("DecodeJSONRequest() status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
