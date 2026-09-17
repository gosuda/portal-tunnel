package x402

import (
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
		next.ServeHTTP(w, forwarded)
	})
}

// settleAndDecorate settles the payment, writing the 402 challenge on failure
// and the settlement response headers on success.
func (p *Payment) settleAndDecorate(w http.ResponseWriter, r *http.Request) (*facilitatortypes.PaymentSettleResponse, bool) {
	settled, ok := p.Settle(r.Context(), w, r)
	if !ok {
		return nil, false
	}
	utils.SetPaymentResponseHeaders(w.Header(), settled)
	return settled, true
}

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
