package types

import (
	"net/http"
	"time"

	facilitatortypes "github.com/gosuda/x402-facilitator/types"
)

// X402RequestBodyLimit is the maximum accepted size of an x402 JSON request body.
const X402RequestBodyLimit int64 = 64 << 10

// X402FacilitatorInfo describes relay-owned x402 control-plane facilitator settings exposed by the API.
type X402FacilitatorInfo struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url,omitempty"`
	Network      string `json:"network,omitempty"`
	NetworkName  string `json:"network_name,omitempty"`
	SupportedURL string `json:"supported_url,omitempty"`
	PayTo        string `json:"pay_to,omitempty"`
}

// X402Payment is the stable x402 payment contract shared by SDK helpers and payment apps.
type X402Payment struct {
	Testnet             bool
	Network             string
	NetworkName         string
	Asset               string
	PayTo               string
	Amount              string
	MaxTimeoutSeconds   int
	RequestTimeout      time.Duration
	Endpoints           []string
	FacilitatorToken    string
	ResourcePath        string
	ResourceDescription string
	ResourceMimeType    string
}

// X402PaymentResult is the successful settlement data passed to protected handlers.
type X402PaymentResult struct {
	TransactionID string
	Network       string
	Payer         string
}

// X402PaymentHandlerFunc handles a request after its x402 payment has settled.
type X402PaymentHandlerFunc func(http.ResponseWriter, *http.Request, X402PaymentResult)

// X402PreparePaymentRequest is the shared prepare endpoint request body.
type X402PreparePaymentRequest struct {
	Sender string `json:"sender"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// X402PreparePaymentResponse is the wallet transaction payload returned by a payment prepare endpoint.
type X402PreparePaymentResponse struct {
	X402Version         int                                  `json:"x402Version"`
	PaymentRequirements facilitatortypes.PaymentRequirements `json:"paymentRequirements"`
	Resource            *facilitatortypes.ResourceInfo       `json:"resource,omitempty"`
	PrepareTransaction  *struct {
		Transaction string `json:"transaction"`
	} `json:"prepareTransaction,omitempty"`
	PaymentTransaction struct {
		Transaction string `json:"transaction"`
	} `json:"paymentTransaction"`
}
