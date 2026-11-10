package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errX402PayToIsRequired              = errors.New("--x402-pay-to is required")
	errX402AmountIsRequired             = errors.New("--x402-amount is required")
	errPhotoURLIsRequired               = errors.New("--photo-url is required")
	errX402MaxTimeoutCannotNegative     = errors.New("--x402-max-timeout cannot be negative")
	errX402RequestTimeoutCannotNegative = errors.New("--x402-request-timeout cannot be negative")
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
	fs := cli.NewFlagSet("payment-app", printUsage)
	registerRunPaymentFlags(fs, &cfg)

	if err := cli.ParseFlagSet(fs, args, printUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "payment-app"); err != nil {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	return runPaymentApp(ctx, cfg)
}

func registerRunPaymentFlags(fs *flag.FlagSet, cfg *paymentConfig) {
	env := cli.NewEnv(os.Environ())
	env.String(fs, &cfg.relayURLs, "relays", "https://localhost", "additional relay API URLs (comma-separated; scheme omitted defaults to https; merged with bootstrap relays when discovery is enabled)", "RELAYS")
	env.Bool(fs, &cfg.discovery, "discovery", false, "include bootstrap relays and enable discovery", "DISCOVERY")
	env.Bool(fs, &cfg.banMITM, "ban-mitm", false, "ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	env.String(fs, &cfg.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	env.String(fs, &cfg.identityJSON, "identity-json", "", "identity json payload kept in memory; takes precedence over --identity-path", "IDENTITY_JSON")
	env.Int(fs, &cfg.maxActiveRelays, "max-active-relays", 3, nil, "maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	fs.StringVar(&cfg.addr, "addr", "127.0.0.1:8093", "local payment app HTTP listen address (host:port or URL)")
	fs.StringVar(&cfg.name, "name", "payment-app", "public hostname prefix (normalized single DNS label, maximum 63 ASCII characters)")
	fs.StringVar(&cfg.desc, "description", "Portal Sui wallet x402 payment app", "lease description")
	fs.StringVar(&cfg.tags, "tags", "payment,x402,sui,usdc,image,photo", "comma-separated lease tags")
	fs.StringVar(&cfg.owner, "owner", "PortalApp Developer", "lease owner")
	fs.StringVar(&cfg.thumbnail, "thumbnail", defaultThumbnailURL, "lease thumbnail")
	fs.StringVar(&cfg.photoURL, "photo-url", defaultPhotoURL, "image URL revealed after payment")
	fs.BoolVar(&cfg.hide, "hide", false, "hide this lease from listings")
	fs.BoolVar(&cfg.x402Testnet, "x402-testnet", true, "use Sui testnet for x402 payments")
	fs.StringVar(&cfg.x402PayTo, "x402-pay-to", "", "Sui USDC recipient address")
	fs.StringVar(&cfg.x402Amount, "x402-amount", "0.01", "USDC amount")
	cli.RepeatedStringFlag(fs, &cfg.x402Endpoints, "x402-rpc", "Sui gRPC endpoint; repeat to try multiple endpoints before defaults")
	fs.IntVar(&cfg.x402MaxTimeoutSeconds, "x402-max-timeout", 0, "x402 max payment timeout seconds advertised to clients")
	fs.IntVar(&cfg.x402RequestTimeout, "x402-request-timeout", 30, "Sui gRPC and x402 verify/settle timeout seconds")
}

func validatePaymentConfig(cfg paymentConfig) error {
	switch {
	case strings.TrimSpace(cfg.x402PayTo) == "":
		return errX402PayToIsRequired
	case strings.TrimSpace(cfg.x402Amount) == "":
		return errX402AmountIsRequired
	case strings.TrimSpace(cfg.photoURL) == "":
		return errPhotoURLIsRequired
	case cfg.x402MaxTimeoutSeconds < 0:
		return errX402MaxTimeoutCannotNegative
	case cfg.x402RequestTimeout < 0:
		return errX402RequestTimeoutCannotNegative
	default:
		return nil
	}
}

func servePaymentExposure(ctx context.Context, cfg paymentConfig, metadata types.LeaseMetadata, handler http.Handler, addr string) error {
	exposure, err := exposeServePaymentExposure(ctx, cfg, metadata)
	if err != nil {
		return err
	}
	defer exposure.Close()

	err = sdk.RunHTTP(ctx, exposure, handler, addr)
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

func exposeServePaymentExposure(ctx context.Context, cfg paymentConfig, metadata types.LeaseMetadata) (*sdk.Exposure, error) {
	listenerIdentity, err := resolvePaymentIdentity(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	explicitRelayURLs, err := utils.NormalizeRelayURLs(utils.SplitCSV(cfg.relayURLs)...)
	if err != nil {
		return nil, err
	}
	opts := []sdk.Option{
		sdk.WithMITMProtection(cfg.banMITM),
		sdk.WithMetadata(metadata),
	}
	if cfg.discovery {
		opts = append(opts, sdk.WithDiscovery(cfg.maxActiveRelays))
	}
	exposure, err := sdk.Expose(ctx, listenerIdentity, explicitRelayURLs, opts...)
	if err != nil {
		return nil, fmt.Errorf("exposure listen error: %w", err)
	}
	return exposure, nil
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

	return servePaymentExposure(ctx, cfg, metadata, handler, addr)
}

func printUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
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

func resolvePaymentIdentity(cfg paymentConfig) (types.Identity, error) {
	if raw := strings.TrimSpace(cfg.identityJSON); raw != "" {
		return identity.Parse([]byte(raw))
	}
	path := strings.TrimSpace(cfg.identityPath)
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return identity.Parse(data)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return types.Identity{}, fmt.Errorf("read identity file: %w", err)
		}
	}
	return generateResolvePaymentIdentity(path, strings.TrimSpace(cfg.name))
}

func generateResolvePaymentIdentity(path, name string) (types.Identity, error) {
	generated, err := identity.Generate(name)
	if err != nil {
		return types.Identity{}, err
	}
	if path == "" {
		return generated, nil
	}
	data, err := identity.Marshal(generated)
	if err != nil {
		return types.Identity{}, err
	}
	if err := utils.EnsureParentDir(path); err != nil {
		return types.Identity{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return types.Identity{}, fmt.Errorf("write identity file: %w", err)
	}
	return generated, nil
}
