package x402

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func TestUSDCPaymentHandlerRejectsOversizedPrepareBody(t *testing.T) {
	t.Parallel()

	handler := &USDCPaymentHandler{payment: &Payment{}}
	body := `{"sender":"` + strings.Repeat("a", int(types.X402RequestBodyLimit)) + `"}`
	req := httptest.NewRequest(http.MethodPost, types.X402PreparePath, strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
