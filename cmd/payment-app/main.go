package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultPhotoURL = "https://image.s-h.day/generated/905a4835ad50.png"

type paymentConfig struct {
	relayURLs       string
	discovery       bool
	banMITM         bool
	identityPath    string
	identityJSON    string
	addr            string
	name            string
	desc            string
	tags            string
	owner           string
	hide            bool
	thumbnail       string
	photoURL        string
	maxActiveRelays int
	x402            types.X402Config
}

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := run(os.Args[1:]); err != nil {
		log.Error().Err(err).Msg("payment app failed")
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := paymentConfig{}
	fs := utils.NewFlagSet("payment-app", printUsage)

	utils.StringFlagEnv(fs, &cfg.relayURLs, "relays", "https://gosunuts.xyz", "additional relay API URLs (comma-separated; scheme omitted defaults to https; merged with bootstrap relays when discovery is enabled)", "RELAYS")
	utils.BoolFlagEnv(fs, &cfg.discovery, "discovery", true, "include bootstrap relays and enable discovery", "DISCOVERY")
	utils.BoolFlagEnv(fs, &cfg.banMITM, "ban-mitm", false, "ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &cfg.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &cfg.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.IntFlagEnv(fs, &cfg.maxActiveRelays, "max-active-relays", 3, nil, "maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	utils.StringFlag(fs, &cfg.addr, "addr", "127.0.0.1:8093", "local payment app HTTP listen address (host:port or URL; disable if empty)")
	utils.StringFlag(fs, &cfg.name, "name", "payment-app", "public hostname prefix (single DNS label)")
	utils.StringFlag(fs, &cfg.desc, "description", "Portal Sui USDC payment app", "lease description")
	utils.StringFlag(fs, &cfg.tags, "tags", "payment,sui,usdc,image,photo", "comma-separated lease tags")
	utils.StringFlag(fs, &cfg.owner, "owner", "PortalApp Developer", "lease owner")
	utils.StringFlag(fs, &cfg.thumbnail, "thumbnail", defaultPhotoURL, "lease thumbnail")
	utils.StringFlag(fs, &cfg.photoURL, "photo-url", defaultPhotoURL, "image URL revealed after payment")
	utils.BoolFlag(fs, &cfg.hide, "hide", false, "hide this lease from listings")
	utils.StringFlag(fs, &cfg.x402.FacilitatorURL, "sui-facilitator-url", "https://gosunuts.xyz/api/x402", "Sui payment facilitator URL, such as https://relay.example.com:4017/api/x402")
	utils.StringFlag(fs, &cfg.x402.Network, "sui-network", types.X402DefaultNetwork, "Sui network for the payment app, such as sui:mainnet or sui:testnet")
	utils.StringFlag(fs, &cfg.x402.Price, "sui-price", "$0.01", "Sui USDC price for the protected image, such as $0.01")
	utils.StringFlag(fs, &cfg.x402.PayTo, "sui-receive-address", "", "Sui receive address; empty uses the payment app Sui payment address")
	utils.StringFlag(fs, &cfg.x402.FacilitatorURL, "x402-facilitator-url", cfg.x402.FacilitatorURL, "advanced: payment facilitator URL")
	utils.StringFlag(fs, &cfg.x402.Network, "x402-network", cfg.x402.Network, "advanced payment rail selector; Sui networks only")
	utils.StringFlag(fs, &cfg.x402.Price, "x402-price", cfg.x402.Price, "advanced: payment price")
	utils.StringFlag(fs, &cfg.x402.PayTo, "x402-pay-to", cfg.x402.PayTo, "advanced: payment receive address")
	fs.IntVar(&cfg.x402.MaxTimeoutSeconds, "x402-max-timeout", 0, "payment max timeout seconds advertised to clients")
	fs.IntVar(&cfg.x402.PaymentTimeoutSecs, "x402-payment-timeout", 0, "payment verify/settle timeout seconds")

	if err := utils.ParseFlagSet(fs, args, printUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "payment-app"); err != nil {
		printUsage(os.Stderr)
		return err
	}
	normalizedName, err := utils.NormalizeDNSLabel(cfg.name)
	if err != nil {
		return fmt.Errorf("invalid --name value: %w", err)
	}
	cfg.name = normalizedName
	if err := validatePaymentConfig(cfg); err != nil {
		return err
	}

	ctx, stop := utils.SignalContext()
	defer stop()

	return runPaymentApp(ctx, cfg)
}

func validatePaymentConfig(cfg paymentConfig) error {
	switch {
	case strings.TrimSpace(cfg.x402.FacilitatorURL) == "":
		return errors.New("--sui-facilitator-url is required")
	case strings.TrimSpace(cfg.x402.Network) == "":
		return errors.New("--sui-network is required")
	case strings.TrimSpace(cfg.x402.Price) == "":
		return errors.New("--sui-price is required")
	case strings.TrimSpace(cfg.photoURL) == "":
		return errors.New("--photo-url is required")
	case cfg.x402.MaxTimeoutSeconds < 0:
		return errors.New("--x402-max-timeout cannot be negative")
	case cfg.x402.PaymentTimeoutSecs < 0:
		return errors.New("--x402-payment-timeout cannot be negative")
	default:
		return nil
	}
}

func runPaymentApp(ctx context.Context, cfg paymentConfig) error {
	metadata := types.LeaseMetadata{
		Description: cfg.desc,
		Tags:        utils.SplitCSV(cfg.tags),
		Owner:       cfg.owner,
		Thumbnail:   cfg.thumbnail,
		Hide:        cfg.hide,
	}
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:       utils.SplitCSV(cfg.relayURLs),
		Discovery:       cfg.discovery,
		Identity:        types.Identity{Name: cfg.name},
		IdentityPath:    cfg.identityPath,
		IdentityJSON:    cfg.identityJSON,
		BanMITM:         cfg.banMITM,
		MaxActiveRelays: cfg.maxActiveRelays,
		Metadata:        metadata,
	})
	if err != nil {
		return fmt.Errorf("exposure listen error: %w", err)
	}
	defer exposure.Close()

	rawAddr := cfg.addr
	cfg.addr, err = utils.NormalizeTargetAddr(cfg.addr)
	if err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", rawAddr, err)
	}
	if strings.TrimSpace(cfg.x402.PayTo) == "" {
		cfg.x402.PayTo = types.X402PayToIdentity
	}
	if strings.TrimSpace(cfg.x402.MimeType) == "" {
		cfg.x402.MimeType = "text/html"
	}

	handler, err := newHandler(paymentHandlerConfig{
		Identity: exposure.Identity(),
		Metadata: metadata,
		X402:     cfg.x402,
		PhotoURL: cfg.photoURL,
	})
	if err != nil {
		return err
	}

	err = exposure.RunHTTP(ctx, handler, cfg.addr)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		return err
	}

	if ctx.Err() != nil {
		log.Info().Msg("payment app shutting down")
	}
	log.Info().Msg("payment app shutdown complete")
	return nil
}

func printUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"payment-app [flags]",
		},
		[]string{
			"payment-app",
			"payment-app --name paid-photo",
			"payment-app --sui-facilitator-url https://relay.example.com:4017/api/x402 --sui-price \"$0.01\"",
		},
	)
}
