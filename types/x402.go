package types

const (
	X402SchemeExact    = "exact"
	X402PayToIdentity  = "identity"
	X402DefaultNetwork = "sui:mainnet"
)

type X402Config struct {
	Network            string `json:"network,omitempty" koanf:"network"`
	Price              string `json:"price,omitempty" koanf:"price"`
	PayTo              string `json:"pay_to,omitempty" koanf:"pay_to"`
	FacilitatorURL     string `json:"facilitator_url,omitempty" koanf:"facilitator_url"`
	Resource           string `json:"resource,omitempty" koanf:"resource"`
	MimeType           string `json:"mime_type,omitempty" koanf:"mime_type"`
	MaxTimeoutSeconds  int    `json:"max_timeout_seconds,omitempty" koanf:"max_timeout_seconds"`
	PaymentTimeoutSecs int    `json:"payment_timeout_seconds,omitempty" koanf:"payment_timeout_seconds"`
}

func (c X402Config) Empty() bool {
	return c.Network == "" &&
		c.Price == "" &&
		c.PayTo == "" &&
		c.FacilitatorURL == "" &&
		c.Resource == "" &&
		c.MimeType == "" &&
		c.MaxTimeoutSeconds == 0 &&
		c.PaymentTimeoutSecs == 0
}

type X402FacilitatorInfo struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url,omitempty"`
	Network      string `json:"network,omitempty"`
	NetworkName  string `json:"network_name,omitempty"`
	SupportedURL string `json:"supported_url,omitempty"`
}

type X402SupportedKind struct {
	X402Version int            `json:"x402Version"`
	Scheme      string         `json:"scheme"`
	Network     string         `json:"network"`
	Extra       map[string]any `json:"extra,omitempty"`
}

type X402SupportedResponse struct {
	Kinds      []X402SupportedKind `json:"kinds"`
	Extensions []string            `json:"extensions"`
	Signers    map[string][]string `json:"signers"`
}
