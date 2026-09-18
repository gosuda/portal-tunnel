package main

import (
	"cmp"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	x402http "github.com/gosuda/x402-facilitator/resource/http"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	suihttp "github.com/gosuda/x402-facilitator/scheme/sui/http"
	facilitatortypes "github.com/gosuda/x402-facilitator/types"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

//go:embed static/index.html static/photo.html static/style.css
var staticFiles embed.FS

const paidPhotoPath = "/paid/photo"

// x402ClientPath and x402PreparePath are this app's shared payment
// endpoints; the values match the agent gateway's contract.
const (
	x402ClientPath  = "/x402/client.js"
	x402PreparePath = "/x402/prepare"
)

const usdcAssetSymbol = "USDC"

// defaultMaxTimeoutSeconds mirrors the gate and preparer defaults so the
// contract the page echoes matches the one clients receive.
const defaultMaxTimeoutSeconds = 60

var (
	indexPage = template.Must(template.ParseFS(staticFiles, "static/index.html"))
	photoPage = template.Must(template.ParseFS(staticFiles, "static/photo.html"))
)

type paymentHandlerConfig struct {
	Metadata          types.LeaseMetadata
	Testnet           bool
	PayTo             string
	Amount            string
	MaxTimeoutSeconds int
	RequestTimeout    time.Duration
	Endpoints         []string
	PhotoURL          string
}

type paymentHandler struct {
	metadata    types.LeaseMetadata
	network     string
	networkName string
	asset       string
	amount      string
	payTo       string
	photoURL    string
}

type paymentPageData struct {
	PageTitle        string
	PageDescription  string
	URL              string
	OGImage          string
	ProtectedPath    string
	Network          string
	NetworkName      string
	Asset            string
	Amount           string
	PhotoURL         string
	RecipientAddress string
	TransactionID    string
	ConfigJSON       template.JS
}

func newHandler(cfg paymentHandlerConfig) (http.Handler, error) {
	handler := &paymentHandler{
		metadata: cfg.Metadata.Copy(),
		photoURL: strings.TrimSpace(cfg.PhotoURL),
	}
	network := suiNetwork(cfg.Testnet)
	asset, ok := suischeme.GetGaslessStablecoinType(network, usdcAssetSymbol)
	if !ok {
		return nil, fmt.Errorf("x402 %s is not registered on %s", usdcAssetSymbol, network)
	}
	payTo := suischeme.NormalizeAddress(cfg.PayTo)
	if payTo == "" {
		return nil, errors.New("x402 USDC payment requires a valid Sui pay-to address")
	}
	amount, err := suischeme.StablecoinAmountToAtomic(network, usdcAssetSymbol, cfg.Amount)
	if err != nil {
		return nil, fmt.Errorf("x402 USDC amount: %w", err)
	}
	maxTimeoutSeconds := cfg.MaxTimeoutSeconds
	if maxTimeoutSeconds <= 0 {
		maxTimeoutSeconds = defaultMaxTimeoutSeconds
	}
	handler.network = network
	handler.networkName = suischeme.GetNetworkName(network)
	handler.asset = asset
	handler.amount = amount
	handler.payTo = payTo
	requirements := facilitatortypes.PaymentRequirements{
		Scheme:            string(facilitatortypes.Exact),
		Network:           network,
		Asset:             asset,
		Amount:            amount,
		PayTo:             payTo,
		MaxTimeoutSeconds: maxTimeoutSeconds,
		Extra: map[string]any{
			"asset":               usdcAssetSymbol,
			"assetTransferMethod": "sui-gasless-stablecoin-address-balance",
		},
	}
	// The facilitator allowlist is pinned to this contract's asset; its
	// default would accept every gasless stablecoin on the network. The
	// facilitator and preparer live as long as the process: newHandler has
	// no closer to hand them to.
	facilitator, err := suifacilitator.NewSuiFacilitatorWithOptions(network, firstNonEmpty(cfg.Endpoints), "", suifacilitator.SuiFacilitatorOptions{
		GaslessStablecoinTypes: []string{asset},
	})
	if err != nil {
		return nil, err
	}
	gate, err := x402http.New(x402http.Config{
		Requirements: requirements,
		Facilitator:  facilitator,
		Resource: &facilitatortypes.ResourceInfo{
			// The gate stamps this configured prefix into every 402
			// challenge; it never sees the per-request absolute URL that
			// the prepare response can advertise.
			URL:         paidPhotoPath,
			Description: cfg.Metadata.Description,
			MimeType:    "text/html",
		},
		RequestTimeout: cfg.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	prepareHandler, err := suihttp.NewPrepareHandler(suihttp.Config{
		Requirements:        requirements,
		ResourcePath:        paidPhotoPath,
		ResourceDescription: cfg.Metadata.Description,
		ResourceMimeType:    "text/html",
		Endpoints:           cfg.Endpoints,
		RequestTimeout:      cfg.RequestTimeout,
	})
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/static/style.css", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.Handle(x402ClientPath, suihttp.ClientHandler())
	mux.Handle(x402PreparePath, prepareHandler)
	mux.HandleFunc("/", handler.handleIndex)
	mux.Handle(paidPhotoPath, gate.Wrap(http.HandlerFunc(handler.renderPaidPhoto)))
	return mux, nil
}

// suiNetwork resolves the CAIP-2 network for the configured stage.
func suiNetwork(testnet bool) string {
	if testnet {
		return "sui:testnet"
	}
	return "sui:mainnet"
}

func firstNonEmpty(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func (h *paymentHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !utils.RequireMethod(w, r, http.MethodGet) {
		return
	}
	data := h.newPaymentPageData(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = indexPage.Execute(w, data)
}

func (h *paymentHandler) renderPaidPhoto(w http.ResponseWriter, r *http.Request) {
	data := h.newPaymentPageData(r)
	data.URL = utils.PublicURLForPath(r, paidPhotoPath)
	if settlement, ok := x402http.SettlementFrom(r.Context()); ok {
		data.TransactionID = settlement.Transaction
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = photoPage.Execute(w, data)
}

func (h *paymentHandler) newPaymentPageData(r *http.Request) paymentPageData {
	description := strings.TrimSpace(h.metadata.Description)
	description = cmp.Or(description, "Connect a Sui wallet, settle USDC with x402, and reveal the protected image.")
	// A formatting failure leaves the atomic string on the page rather than
	// hiding the contract the payment is settled against.
	amount := h.amount
	if formatted, err := suischeme.FormatStablecoinAtomicAmount(h.network, usdcAssetSymbol, h.amount); err == nil {
		amount = formatted
	}
	config := map[string]any{
		"network":       h.network,
		"networkName":   h.networkName,
		"asset":         h.asset,
		"amount":        h.amount,
		"payTo":         h.payTo,
		"preparePath":   x402PreparePath,
		"protectedPath": paidPhotoPath,
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		configJSON = []byte("{}")
	}
	return paymentPageData{
		PageTitle:        "Portal Sui Wallet Payment",
		PageDescription:  description,
		URL:              utils.PublicURLForPath(r, "/"),
		OGImage:          h.metadata.Thumbnail,
		ProtectedPath:    paidPhotoPath,
		Network:          h.network,
		NetworkName:      h.networkName,
		Asset:            h.asset,
		Amount:           amount,
		PhotoURL:         h.photoURL,
		RecipientAddress: h.payTo,
		ConfigJSON:       template.JS(string(configJSON)),
	}
}
