package x402

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Wrap gates next behind this payment: requests without a verifiable payment
// receive the 402 challenge, paid requests are verified and settled against
// the facilitator, payment headers are stripped before the request is
// forwarded, and the settlement receipt is published as payment response
// headers. Methods outside the configured payment methods bypass the gate
// untouched.
func (p *Payment) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.paidMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		p.wrapPaid(next).ServeHTTP(w, r)
	})
}

// wrapPaid settles the request before forwarding it to next.
func (p *Payment) wrapPaid(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.settleAndDecorate(w, r); !ok {
			return
		}
		forwarded := r.Clone(r.Context())
		utils.StripPaymentHeaders(forwarded.Header)
		receipt := w.Header().Get(types.HeaderPaymentResponse)
		response := &paymentResponseWriter{ResponseWriter: w, receipt: receipt}
		next.ServeHTTP(response, forwarded)
		if !response.wroteHeader {
			response.WriteHeader(http.StatusOK)
		}
	})
}

// settleAndDecorate settles the payment, writing the 402 challenge on failure
// and the settlement response headers on success.
func (p *Payment) settleAndDecorate(w http.ResponseWriter, r *http.Request) (*facilitatortypes.PaymentSettleResponse, bool) {
	settled, ok := p.Settle(r.Context(), w, r)
	if !ok {
		return nil, false
	}
	setPaymentResponseHeaders(w.Header(), settled)
	return settled, true
}

func writePaymentJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func setPaymentResponseHeaders(header http.Header, settled *facilitatortypes.PaymentSettleResponse) {
	if header == nil || settled == nil {
		return
	}
	raw, err := json.Marshal(settled)
	if err != nil {
		return
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	header.Set(types.HeaderPaymentResponse, encoded)
	header.Set(types.HeaderXPaymentResponse, encoded)
}

// paymentResponseWriter keeps the trusted settlement receipt ahead of any
// headers written by the downstream handler.
type paymentResponseWriter struct {
	http.ResponseWriter
	receipt     string
	wroteHeader bool
}

func (w *paymentResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	utils.StripPaymentHeaders(w.Header())
	if w.receipt != "" {
		w.Header().Set(types.HeaderPaymentResponse, w.receipt)
		w.Header().Set(types.HeaderXPaymentResponse, w.receipt)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *paymentResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *paymentResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *paymentResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// paidMethod reports whether method is subject to payment. An empty method
// list pays every method.
func (p *Payment) paidMethod(method string) bool {
	if p == nil || len(p.methods) == 0 {
		return true
	}
	_, ok := p.methods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

// PrepareHandler serves the shared wallet prepare endpoint: it accepts the
// POSTed prepare request and returns the transaction payload for this
// payment's requirements.
func (p *Payment) PrepareHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !utils.RequireMethod(w, r, http.MethodPost) {
			return
		}
		req, ok := utils.DecodeJSONRequestAs[types.X402PreparePaymentRequest](w, r, types.X402RequestBodyLimit, utils.APIErrorResponse{
			Status:  http.StatusBadRequest,
			Code:    types.APIErrorCodeInvalidJSON,
			Message: "invalid payment prepare request",
		})
		if !ok {
			return
		}
		p.WritePrepare(w, r, req.Sender, utils.NormalizeURLPath(req.Path))
	})
}

// ClientJSHandler serves the shared browser x402 wallet/payment client.
func (p *Payment) ClientJSHandler() http.Handler {
	return http.HandlerFunc(ServeClientJS)
}
