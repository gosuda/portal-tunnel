package main

import (
	"cmp"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

//go:embed static/index.html static/photo.html static/style.css
var staticFiles embed.FS

const paidPhotoPath = "/paid/photo"

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
	paidPhotoHandler, err := x402.NewUSDCPaymentHandler(types.X402Payment{
		Testnet:             cfg.Testnet,
		PayTo:               cfg.PayTo,
		Amount:              cfg.Amount,
		MaxTimeoutSeconds:   cfg.MaxTimeoutSeconds,
		RequestTimeout:      cfg.RequestTimeout,
		Endpoints:           cfg.Endpoints,
		ResourcePath:        paidPhotoPath,
		ResourceDescription: cfg.Metadata.Description,
		ResourceMimeType:    "text/html",
	}, paidPhotoPath, http.MethodGet, handler.renderPaidPhoto)
	if err != nil {
		return nil, err
	}
	payment := paidPhotoHandler.Payment()
	handler.network = payment.Network
	handler.networkName = payment.NetworkName
	handler.asset = payment.Asset
	handler.amount = payment.Amount
	handler.payTo = payment.PayTo

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/static/style.css", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc(types.X402ClientPath, x402.ServeClientJS)
	mux.Handle(types.X402PreparePath, paidPhotoHandler)
	mux.HandleFunc("/", handler.handleIndex)
	mux.Handle(paidPhotoPath, paidPhotoHandler)
	return mux, nil
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

func (h *paymentHandler) renderPaidPhoto(w http.ResponseWriter, r *http.Request, result types.X402PaymentResult) {
	data := h.newPaymentPageData(r)
	data.URL = utils.PublicURLForPath(r, paidPhotoPath)
	data.TransactionID = result.TransactionID
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = photoPage.Execute(w, data)
}

func (h *paymentHandler) newPaymentPageData(r *http.Request) paymentPageData {
	description := strings.TrimSpace(h.metadata.Description)
	description = cmp.Or(description, "Connect a Sui wallet, settle USDC with x402, and reveal the protected image.")
	config := map[string]any{
		"network":       h.network,
		"networkName":   h.networkName,
		"asset":         h.asset,
		"amount":        h.amount,
		"payTo":         h.payTo,
		"preparePath":   types.X402PreparePath,
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
		Amount:           x402.FormatUSDCAtomicAmount(h.amount),
		PhotoURL:         h.photoURL,
		RecipientAddress: h.payTo,
		ConfigJSON:       template.JS(string(configJSON)),
	}
}
