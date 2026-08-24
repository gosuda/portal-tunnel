package x402

import (
	"cmp"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

//go:embed client.js
var clientJS []byte

// ServeClientJS serves the shared browser x402 wallet/payment client.
func ServeClientJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead && !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(clientJS)
}

// USDCPaymentHandler serves both the wallet prepare endpoint and one protected resource.
type USDCPaymentHandler struct {
	payment       *Payment
	protectedPath string
	method        string
	handler       types.X402PaymentHandlerFunc
}

// NewUSDCPaymentHandler returns a complete HTTP handler for one Sui USDC x402 payment flow.
func NewUSDCPaymentHandler(payment types.X402Payment, protectedPath, protectedMethod string, handler types.X402PaymentHandlerFunc) (*USDCPaymentHandler, error) {
	if handler == nil {
		return nil, errors.New("USDC payment handler is required")
	}
	paid, err := NewUSDCPayment(payment)
	if err != nil {
		return nil, err
	}
	payment = paid.payment

	protectedPath = strings.TrimSpace(protectedPath)
	protectedPath = cmp.Or(protectedPath, payment.ResourcePath)
	if protectedPath == "" {
		return nil, errors.New("USDC payment protected path is required")
	}
	if !strings.HasPrefix(protectedPath, "/") {
		return nil, fmt.Errorf("USDC payment protected path %q must start with /", protectedPath)
	}
	protectedPath = utils.NormalizeURLPath(protectedPath)
	if protectedPath == types.X402PreparePath {
		return nil, fmt.Errorf("USDC payment protected path cannot be %s", types.X402PreparePath)
	}

	paid.payment.ResourcePath = protectedPath
	return &USDCPaymentHandler{
		payment:       paid,
		protectedPath: protectedPath,
		method:        strings.TrimSpace(protectedMethod),
		handler:       handler,
	}, nil
}

// Payment returns the normalized payment contract used by this handler.
func (h *USDCPaymentHandler) Payment() types.X402Payment {
	if h == nil || h.payment == nil {
		return types.X402Payment{}
	}
	return h.payment.payment
}

func (h *USDCPaymentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.payment == nil {
		http.Error(w, "payment is not configured", http.StatusInternalServerError)
		return
	}

	path := "/"
	if r.URL != nil {
		path = r.URL.Path
	}
	switch path {
	case types.X402PreparePath:
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
		h.payment.WritePrepare(w, r, req.Sender, h.protectedPath)
	case h.protectedPath:
		if h.method != "" && !utils.RequireMethod(w, r, h.method) {
			return
		}
		if h.handler == nil {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()
		cancel := func() {}
		payment := h.payment.payment
		if payment.RequestTimeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, payment.RequestTimeout)
		}
		defer cancel()

		settled, ok := h.payment.Settle(ctx, w, r)
		if !ok {
			return
		}
		utils.SetPaymentResponseHeaders(w.Header(), settled)

		h.handler(w, r, types.X402PaymentResult{
			TransactionID: strings.TrimSpace(settled.Transaction),
			Network:       string(settled.Network),
			Payer:         strings.TrimSpace(settled.Payer),
		})
	default:
		http.NotFound(w, r)
	}
}
