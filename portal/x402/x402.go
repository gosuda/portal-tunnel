package x402

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strings"

	facilitatorapi "github.com/gosuda/x402-facilitator/api"
	facilitatorcore "github.com/gosuda/x402-facilitator/facilitator"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	MainnetNetwork = "sui:mainnet"
	TestnetNetwork = "sui:testnet"

	defaultMaxTimeoutSeconds = 60
)

var networkDisplayNames = map[string]string{
	MainnetNetwork: "Sui Mainnet",
	TestnetNetwork: "Sui Testnet",
}

func Network(testnet bool) string {
	if testnet {
		return TestnetNetwork
	}
	return MainnetNetwork
}

func NetworkDisplayName(network string) string {
	return networkDisplayNames[strings.TrimSpace(strings.ToLower(network))]
}

type FacilitatorConfig struct {
	Testnet bool
}

func MountFacilitator(mux *http.ServeMux, cfg FacilitatorConfig) error {
	if mux == nil {
		return errors.New("x402 facilitator requires an api mux")
	}
	facilitator, err := newUSDCFacilitator(Network(cfg.Testnet), "")
	if err != nil {
		return fmt.Errorf("create sui x402 facilitator: %w", err)
	}
	mux.Handle(types.PathX402Facilitator+"/", http.StripPrefix(types.PathX402Facilitator, facilitatorapi.NewServer(facilitator)))
	return nil
}

func usdcAsset(network string) (string, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	asset, ok := suischeme.GetGaslessStablecoinType(network, "USDC")
	if !ok {
		return "", fmt.Errorf("USDC is not gasless stablecoin allowlisted on %s", network)
	}
	return asset, nil
}

func newUSDCFacilitator(network, asset string, endpoints ...string) (facilitatorcore.Facilitator, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	network = cmp.Or(network, MainnetNetwork)
	if asset == "" {
		var err error
		asset, err = usdcAsset(network)
		if err != nil {
			return nil, err
		}
	}
	url := ""
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			url = endpoint
			break
		}
	}
	return facilitatorcore.NewSuiFacilitatorWithOptions(network, url, "", facilitatorcore.SuiFacilitatorOptions{
		GaslessStablecoinTypes: []string{asset},
	})
}
