package gateway

import (
	"cmp"
	"fmt"
	"net/url"
	"strings"

	facilitatorclient "github.com/gosuda/x402-facilitator/api/client"
	x402http "github.com/gosuda/x402-facilitator/resource/http"
	casperscheme "github.com/gosuda/x402-facilitator/scheme/casper"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func newCasperFacilitatorClient(contract X402Config) (*facilitatorclient.Client, error) {
	endpoint := cmp.Or(firstEndpoint(contract.Endpoints), casperscheme.DefaultFacilitatorURL)
	token := strings.TrimSpace(contract.FacilitatorToken)
	if token == "" && strings.EqualFold(strings.TrimRight(endpoint, "/"), casperscheme.DefaultFacilitatorURL) {
		return nil, errCsprCloudX402FacilitatorRequiresAuthorization
	}
	if token != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse x402 facilitator endpoint %q: %w", endpoint, err)
		}
		if u.Scheme == "http" && !utils.IsLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("x402 facilitator endpoint %q sends the authorization token over plaintext http; use https or a loopback endpoint", endpoint)
		}
	}
	client, err := facilitatorclient.NewClient(endpoint)
	if err != nil {
		return nil, fmt.Errorf("create casper x402 facilitator: %w", err)
	}
	if token != "" {
		client.CreateAuthHeader = func() (map[string]map[string]string, error) {
			return map[string]map[string]string{
				"verify": {"Authorization": token},
				"settle": {"Authorization": token},
			}, nil
		}
	}
	return client, nil
}

func firstEndpoint(endpoints []string) string {
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			return endpoint
		}
	}
	return ""
}

func canonicalRequirements(requirements facilitatortypes.PaymentRequirements) facilitatortypes.PaymentRequirements {
	extra := make(map[string]any, len(requirements.Extra)+1)
	for key, value := range requirements.Extra {
		extra[key] = value
	}
	extra["paymentFlow"] = x402http.PaymentFlowUpfront
	requirements.Extra = extra
	return requirements
}
