package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultThumbnailURL = "https://image.portal.thumbgo.kr/generated/1e56ad0f0a1d.png"
	defaultPhotoURL     = "https://image.portal.thumbgo.kr/generated/905a4835ad50.png"
)

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

	x402Testnet           bool
	x402PayTo             string
	x402Amount            string
	x402Endpoints         []string
	x402MaxTimeoutSeconds int
	x402RequestTimeout    int
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

	utils.StringFlagEnv(fs, &cfg.relayURLs, "relays", "https://localhost", "additional relay API URLs (comma-separated; scheme omitted defaults to https; merged with bootstrap relays when discovery is enabled)", "RELAYS")
	utils.BoolFlagEnv(fs, &cfg.discovery, "discovery", false, "include bootstrap relays and enable discovery", "DISCOVERY")
	utils.BoolFlagEnv(fs, &cfg.banMITM, "ban-mitm", false, "ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &cfg.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &cfg.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.IntFlagEnv(fs, &cfg.maxActiveRelays, "max-active-relays", 3, nil, "maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	utils.StringFlag(fs, &cfg.addr, "addr", "127.0.0.1:8093", "local payment app HTTP listen address (host:port or URL)")
	utils.StringFlag(fs, &cfg.name, "name", "payment-app", "public hostname prefix (single DNS label)")
	utils.StringFlag(fs, &cfg.desc, "description", "Portal Sui wallet x402 payment app", "lease description")
	utils.StringFlag(fs, &cfg.tags, "tags", "payment,x402,sui,usdc,image,photo", "comma-separated lease tags")
	utils.StringFlag(fs, &cfg.owner, "owner", "PortalApp Developer", "lease owner")
	utils.StringFlag(fs, &cfg.thumbnail, "thumbnail", defaultThumbnailURL, "lease thumbnail")
	utils.StringFlag(fs, &cfg.photoURL, "photo-url", defaultPhotoURL, "image URL revealed after payment")
	utils.BoolFlag(fs, &cfg.hide, "hide", false, "hide this lease from listings")
	utils.BoolFlag(fs, &cfg.x402Testnet, "x402-testnet", true, "use Sui testnet for x402 payments")
	utils.StringFlag(fs, &cfg.x402PayTo, "x402-pay-to", "", "Sui USDC recipient address")
	utils.StringFlag(fs, &cfg.x402Amount, "x402-amount", "0.01", "USDC amount")
	utils.RepeatedStringFlag(fs, &cfg.x402Endpoints, "x402-rpc", "Sui gRPC endpoint; repeat to try multiple endpoints before defaults")
	fs.IntVar(&cfg.x402MaxTimeoutSeconds, "x402-max-timeout", 0, "x402 max payment timeout seconds advertised to clients")
	fs.IntVar(&cfg.x402RequestTimeout, "x402-request-timeout", 30, "Sui gRPC and x402 verify/settle timeout seconds")

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
	case strings.TrimSpace(cfg.x402PayTo) == "":
		return errors.New("--x402-pay-to is required")
	case strings.TrimSpace(cfg.x402Amount) == "":
		return errors.New("--x402-amount is required")
	case strings.TrimSpace(cfg.photoURL) == "":
		return errors.New("--photo-url is required")
	case cfg.x402MaxTimeoutSeconds < 0:
		return errors.New("--x402-max-timeout cannot be negative")
	case cfg.x402RequestTimeout < 0:
		return errors.New("--x402-request-timeout cannot be negative")
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
	rawAddr := cfg.addr
	addr, err := utils.NormalizeTargetAddr(cfg.addr)
	if err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", rawAddr, err)
	}

	handler, err := newHandler(paymentHandlerConfig{
		Metadata:          metadata,
		Testnet:           cfg.x402Testnet,
		PayTo:             cfg.x402PayTo,
		Amount:            cfg.x402Amount,
		MaxTimeoutSeconds: cfg.x402MaxTimeoutSeconds,
		RequestTimeout:    time.Duration(cfg.x402RequestTimeout) * time.Second,
		Endpoints:         cfg.x402Endpoints,
		PhotoURL:          cfg.photoURL,
	})
	if err != nil {
		return err
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

	err = exposure.RunHTTP(ctx, handler, addr)
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
			"payment-app --x402-pay-to SUI_ADDRESS [flags]",
		},
		[]string{
			"payment-app --x402-pay-to 0x...",
			"payment-app --name paid-photo --x402-pay-to 0x... --x402-amount 0.01",
			"payment-app --x402-testnet=false --x402-pay-to 0x... --x402-amount 0.01",
		},
	)
}
