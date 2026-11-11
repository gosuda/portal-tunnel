package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	facilitatorapi "github.com/gosuda/x402-facilitator/api"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errX402FacilitatorRequiresValidSuiPay = errors.New("x402 facilitator requires a valid Sui pay-to address")
)

type x402FacilitatorSettings struct {
	Enabled bool
	Testnet bool
	PayTo   string
}

func resolveX402Facilitator(cfg appConfig) (x402FacilitatorSettings, error) {
	if !cfg.X402Enabled {
		return x402FacilitatorSettings{}, nil
	}
	payTo := suischeme.NormalizeAddress(cfg.X402PayTo)
	if payTo == "" {
		return x402FacilitatorSettings{}, errX402FacilitatorRequiresValidSuiPay
	}
	return x402FacilitatorSettings{Enabled: true, Testnet: cfg.X402Testnet, PayTo: payTo}, nil
}

const (
	pathX402Facilitator = "/api/x402"
	x402SupportedPath   = pathX402Facilitator + "/supported"
)

type x402FacilitatorInfo struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url,omitempty"`
	Network      string `json:"network,omitempty"`
	NetworkName  string `json:"network_name,omitempty"`
	SupportedURL string `json:"supported_url,omitempty"`
	PayTo        string `json:"pay_to,omitempty"`
}

type domainResponse struct {
	types.DomainResponse
	X402 x402FacilitatorInfo `json:"x402"`
}

func mountRelayRoutes(settings x402FacilitatorSettings, server *portal.Server, mux *http.ServeMux) error {
	network := "sui:mainnet"
	if settings.Testnet {
		network = "sui:testnet"
	}

	if settings.Enabled {
		asset, ok := suischeme.GetGaslessStablecoinType(network, "USDC")
		if !ok {
			return fmt.Errorf("x402 USDC is not registered on %s", network)
		}
		facilitator, err := suifacilitator.NewSuiFacilitatorWithOptions(network, "", "", suifacilitator.SuiFacilitatorOptions{
			GaslessStablecoinTypes: []string{asset},
		})
		if err != nil {
			return fmt.Errorf("mount x402 facilitator: %w", err)
		}
		mux.Handle(pathX402Facilitator+"/", http.StripPrefix(pathX402Facilitator, facilitatorapi.NewServer(facilitator)))
		log.Info().Str("path", pathX402Facilitator).Str("network", network).Msg("relay-owned x402 facilitator enabled")
	}

	mux.HandleFunc(types.PathSDKDomain, func(w http.ResponseWriter, r *http.Request) {
		if !utils.RequireMethod(w, r, http.MethodGet) {
			return
		}
		report := domainResponse{DomainResponse: server.DomainReport()}
		if settings.Enabled {
			baseURL := strings.TrimRight(server.PortalURL(), "/")
			report.X402 = x402FacilitatorInfo{
				Enabled:      true,
				URL:          baseURL + pathX402Facilitator,
				Network:      network,
				NetworkName:  suischeme.GetNetworkName(network),
				SupportedURL: baseURL + x402SupportedPath,
				PayTo:        settings.PayTo,
			}
		}
		utils.WriteAPIData(w, http.StatusOK, report)
	})
	return nil
}
