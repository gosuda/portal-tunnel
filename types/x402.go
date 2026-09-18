package types

import (
	"net/http"
	"time"
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
	// Methods limits payment enforcement to these HTTP methods, matched
	// case-insensitively. Empty means every method is paid.
	Methods []string
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

// X402PaymentRequirements describes the accepted payment published to wallets.
// It mirrors the x402 v2 payment-requirements wire object in Portal terms.
type X402PaymentRequirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	Amount            string         `json:"amount"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// X402ResourceInfo describes the protected resource published to wallets.
type X402ResourceInfo struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// X402PreparePaymentResponse is the wallet transaction payload returned by a payment prepare endpoint.
type X402PreparePaymentResponse struct {
	X402Version         int                     `json:"x402Version"`
	PaymentRequirements X402PaymentRequirements `json:"paymentRequirements"`
	Resource            *X402ResourceInfo       `json:"resource,omitempty"`
	PrepareTransaction  *struct {
		Transaction string `json:"transaction"`
	} `json:"prepareTransaction,omitempty"`
	PaymentTransaction struct {
		Transaction string `json:"transaction"`
	} `json:"paymentTransaction"`
}
