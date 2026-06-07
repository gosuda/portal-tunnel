package main

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	portalx402 "github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
)

//go:embed static/index.html static/style.css
var staticFiles embed.FS

const paidPhotoPath = "/paid/photo"

var (
	indexPage = template.Must(template.ParseFS(staticFiles, "static/index.html"))
	photoPage = template.Must(template.New("photo").Parse(`<!DOCTYPE html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.PageTitle}}</title>
  <meta name="description" content="{{.PageDescription}}">
  <meta property="og:type" content="website">
  <meta property="og:title" content="{{.PageTitle}}">
  <meta property="og:description" content="{{.PageDescription}}">
  <meta property="og:image" content="{{.OGImage}}">
  <meta property="og:url" content="{{.URL}}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{{.PageTitle}}">
  <meta name="twitter:description" content="{{.PageDescription}}">
  <meta name="twitter:image" content="{{.OGImage}}">
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      padding: 0;
      background: #f7f8fb;
      color: #182033;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    main {
      display: grid;
      width: 100%;
      min-height: 100vh;
      grid-template-rows: minmax(0, 1fr) auto;
      overflow: hidden;
      background: #ffffff;
    }
    img {
      width: 100%;
      height: 100%;
      min-height: 0;
      display: block;
      object-fit: contain;
      background: #111827;
    }
    section {
      display: grid;
      gap: 10px;
      padding: 18px;
      border-top: 1px solid #e5eaf0;
    }
    .eyebrow {
      margin: 0;
      color: #0e7490;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    h1 {
      margin: 0;
      color: #111827;
      font-size: 25px;
      line-height: 1.18;
    }
    p {
      margin: 0;
      color: #4b5565;
      font-size: 15px;
      line-height: 1.55;
    }
    dl {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin: 4px 0 0;
    }
    div { min-width: 0; }
    dt {
      color: #667085;
      font-size: 12px;
      font-weight: 700;
    }
    dd {
      margin: 4px 0 0;
      overflow-wrap: anywhere;
      color: #111827;
      font-size: 13px;
      font-weight: 750;
    }
    @media (max-width: 640px) {
      section { padding: 14px; }
      dl { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <img src="{{.PhotoURL}}" alt="Unlocked protected image">
    <section>
      <p class="eyebrow">{{.PaymentRailName}} complete</p>
      <h1>Image unlocked</h1>
      <p>The protected image is available after the {{.Price}} {{.SettlementLabel}}.</p>
      <dl>
        <div>
          <dt>Amount</dt>
          <dd>{{.Price}}</dd>
        </div>
        <div>
          <dt>Asset</dt>
          <dd>{{.AssetLabel}}</dd>
        </div>
        <div>
          <dt>{{.NetworkLabel}}</dt>
          <dd>{{.NetworkName}}</dd>
        </div>
        <div>
          <dt>{{.RecipientLabel}}</dt>
          <dd>{{.RecipientAddress}}</dd>
        </div>
      </dl>
    </section>
  </main>
</body>
`))
)

type paymentHandlerConfig struct {
	Identity types.Identity
	Metadata types.LeaseMetadata
	X402     types.X402Config
	PhotoURL string
}

type paymentPageData struct {
	PageTitle        string
	PageDescription  string
	URL              string
	OGImage          string
	ProtectedPath    string
	Price            string
	NetworkName      string
	NetworkLabel     string
	PaymentRailName  string
	Headline         string
	Lede             string
	AssetLabel       string
	RecipientLabel   string
	PhotoURL         string
	RecipientAddress string
	ButtonLabel      string
	StatusReady      string
	StatusOpen       string
	StatusPaused     string
	PreviewTitle     string
	PreviewLabel     string
	PreviewMessage   string
	CheckoutTitle    string
	LockedMark       string
	SettlementLabel  string
}

func newHandler(cfg paymentHandlerConfig) (http.Handler, error) {
	staticFS, _ := fs.Sub(staticFiles, "static")
	pageData := newPaymentPageData(cfg)

	mux := http.NewServeMux()
	mux.Handle("/static/style.css", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := pageData
		data.URL = requestURL(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = indexPage.Execute(w, data)
	})

	photoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := pageData
		data.URL = requestURL(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = photoPage.Execute(w, data)
	})
	routeX402 := cfg.X402
	routeX402.Price = pageData.Price
	if strings.TrimSpace(routeX402.Resource) == "" {
		routeX402.Resource = paidPhotoPath
	}
	if strings.TrimSpace(routeX402.MimeType) == "" {
		routeX402.MimeType = "text/html"
	}
	protectedPhoto, err := portalx402.NewHTTPRouteHandler(portalx402.HTTPRouteHandlerConfig{
		Prefix:         paidPhotoPath,
		Next:           photoHandler,
		X402:           routeX402,
		TunnelIdentity: cfg.Identity,
		Metadata:       cfg.Metadata,
	})
	if err != nil {
		return nil, err
	}
	mux.Handle(paidPhotoPath, protectedPhoto)
	mux.Handle(paidPhotoPath+"/", protectedPhoto)

	return mux, nil
}

func newPaymentPageData(cfg paymentHandlerConfig) paymentPageData {
	network := strings.TrimSpace(cfg.X402.Network)
	networkName := portalx402.NetworkDisplayName(network)
	if networkName == "" {
		networkName = network
	}
	suiPayment := isSuiPaymentNetwork(network)
	recipient := strings.TrimSpace(cfg.X402.PayTo)
	if recipient == "" || strings.EqualFold(recipient, types.X402PayToIdentity) {
		if suiPayment {
			recipient = cfg.Identity.SuiAddress
		} else {
			recipient = cfg.Identity.Address
		}
	}
	price := strings.TrimSpace(cfg.X402.Price)
	description := strings.TrimSpace(cfg.Metadata.Description)
	if description == "" {
		if suiPayment {
			description = "Pay " + price + " in Sui USDC to reveal the protected image."
		} else {
			description = "Pay " + price + " to reveal the protected image."
		}
	}

	page := paymentPageData{
		PageTitle:        "Portal Payment",
		PageDescription:  description,
		OGImage:          strings.TrimSpace(cfg.PhotoURL),
		ProtectedPath:    paidPhotoPath,
		Price:            price,
		NetworkName:      networkName,
		NetworkLabel:     "Network",
		PaymentRailName:  "Payment",
		Headline:         "Paid image delivery",
		Lede:             description,
		AssetLabel:       "Stablecoin",
		RecipientLabel:   "Recipient",
		PhotoURL:         strings.TrimSpace(cfg.PhotoURL),
		RecipientAddress: recipient,
		ButtonLabel:      "Open checkout",
		StatusReady:      "Ready",
		StatusOpen:       "Checkout open",
		StatusPaused:     "Checkout paused",
		PreviewTitle:     "Protected image",
		PreviewLabel:     "Protected image",
		PreviewMessage:   "Awaiting payment",
		CheckoutTitle:    "Payment checkout",
		LockedMark:       "402",
		SettlementLabel:  "payment settles",
	}
	if suiPayment {
		page.PageTitle = "Portal Sui Payment"
		page.NetworkLabel = "Chain"
		page.PaymentRailName = "Sui payment"
		page.Headline = "Sui image unlock"
		page.AssetLabel = "Sui USDC"
		page.RecipientLabel = "Sui receive address"
		page.ButtonLabel = "Pay with Sui"
		page.StatusReady = "Sui checkout ready"
		page.StatusOpen = "Sui checkout open"
		page.StatusPaused = "Sui checkout paused"
		page.PreviewLabel = "Sui payment required"
		page.PreviewMessage = "Awaiting Sui payment"
		page.CheckoutTitle = "Sui payment checkout"
		page.LockedMark = "SUI"
		page.SettlementLabel = "Sui USDC payment settles"
	}
	return page
}

func isSuiPaymentNetwork(network string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "sui:")
}

func requestURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
		scheme = strings.TrimSpace(strings.Split(forwardedProto, ",")[0])
	}
	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host + r.URL.Path
}
