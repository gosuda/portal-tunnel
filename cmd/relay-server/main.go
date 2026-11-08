package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	facilitatorapi "github.com/gosuda/x402-facilitator/api"
	suischeme "github.com/gosuda/x402-facilitator/scheme/sui"
	suifacilitator "github.com/gosuda/x402-facilitator/scheme/sui/facilitator"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errX402FacilitatorRequiresValidSuiPay = errors.New("x402 facilitator requires a valid Sui pay-to address")
	errOnlyOneHelpTopicSupported          = errors.New("only one help topic is supported")
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := cli.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]cli.CommandFunc{
		"":       runServeCommand,
		"serve":  runServeCommand,
		"config": runConfigCommand,
		"help":   runHelpCommand,
	}); err != nil {
		log.Error().Err(err).Msg("execute root command")
		os.Exit(1)
	}
}

type appConfig struct {
	Relay             portal.ServerConfig
	UDPEnabled        bool
	TCPEnabled        bool
	PreAuth           policy.PreAuthConfig
	ApprovalMode      string
	TrustProxyHeaders bool
	TrustedProxyCIDRs string
	TunnelSourceCIDRs string
	FrontendDir       string
	AdminToken        string
	PprofEnabled      bool
	PprofListenAddr   string
	// Relay-owned x402 facilitator surface: portal.Server is x402-blind, so
	// this application resolves the flags and mounts the payment endpoints.
	X402Enabled bool
	X402Testnet bool
	X402PayTo   string
}

// resolveAppConfig registers every flag and resolves it against the
// supplied environment. The config subcommand reuses it so that inspecting a
// deployment and running it read the same definitions.
func resolveAppConfig(args []string, environ []string) (appConfig, *cli.Env, error) {
	env := cli.NewEnv(environ)

	cfg := appConfig{}
	fs := cli.NewFlagSet("relay-server", printRootUsage)
	registerAppFlags(fs, &cfg, env)

	if err := cli.ParseFlagSet(fs, args, printRootUsage); err != nil {
		return appConfig{}, env, err
	}
	if err := cli.RequireNoArgs(fs.Args(), "relay-server"); err != nil {
		printRootUsage(os.Stderr)
		return appConfig{}, env, err
	}
	cfg.Relay.StateDir = strings.TrimSpace(cfg.Relay.StateDir)
	return cfg, env, nil
}

func registerAppFlags(fs *flag.FlagSet, cfg *appConfig, env *cli.Env) {
	preAuthDefaults := policy.DefaultPreAuthConfig()
	env.Int(fs, &cfg.PreAuth.SourcePerMinute, "preauth-source-per-minute", preAuthDefaults.SourcePerMinute, nil, "per-source pre-auth units refilled per minute", "PREAUTH_SOURCE_PER_MINUTE")
	env.Int(fs, &cfg.PreAuth.SourceBurst, "preauth-source-burst", preAuthDefaults.SourceBurst, nil, "per-source pre-auth burst units", "PREAUTH_SOURCE_BURST")
	env.Int(fs, &cfg.PreAuth.GlobalPerMinute, "preauth-global-per-minute", preAuthDefaults.GlobalPerMinute, nil, "global pre-auth units refilled per minute", "PREAUTH_GLOBAL_PER_MINUTE")
	env.Int(fs, &cfg.PreAuth.GlobalBurst, "preauth-global-burst", preAuthDefaults.GlobalBurst, nil, "global pre-auth burst units", "PREAUTH_GLOBAL_BURST")
	env.Int(fs, &cfg.PreAuth.ChallengeCost, "preauth-challenge-cost", preAuthDefaults.ChallengeCost, nil, "pre-auth units per registration challenge", "PREAUTH_CHALLENGE_COST")
	env.Int(fs, &cfg.PreAuth.AnnounceCost, "preauth-announce-cost", preAuthDefaults.AnnounceCost, nil, "pre-auth units per discovery announce", "PREAUTH_ANNOUNCE_COST")
	env.Int(fs, &cfg.PreAuth.RegisterCost, "preauth-register-cost", preAuthDefaults.RegisterCost, nil, "pre-auth units per registration attempt", "PREAUTH_REGISTER_COST")

	env.Bool(fs, &cfg.Relay.Cache.Enabled, "cache-enabled", true, "allow explicitly opted-in static exposures to use the relay disk cache", "CACHE_ENABLED")
	env.Int(fs, &cfg.Relay.Cache.MaxBytes, "cache-max-bytes", 1<<30, nil, "maximum relay cached and staging payload bytes", "CACHE_MAX_BYTES")
	env.Duration(fs, &cfg.Relay.Cache.MaxTTL, "cache-max-ttl", 24*time.Hour, "maximum offline cache lifetime after unregister or lease expiry", "CACHE_MAX_TTL")
	env.String(fs, &cfg.Relay.PortalURL, "portal-url", "https://localhost", "portal base URL", "PORTAL_URL")
	env.String(fs, &cfg.FrontendDir, "frontend-dir", "", "custom SPA directory containing index.html; embedded frontend is used when empty", "PORTAL_FRONTEND_DIR")
	env.String(fs, &cfg.Relay.StateDir, "identity-path", "./.portal-certs", "directory path for relay identity, policy state, and keyless materials", "IDENTITY_PATH")
	env.CSV(fs, &cfg.Relay.Bootstraps, "bootstraps", "", "bootstrap relay API URLs; merged with bootstrap relays when discovery is enabled", "BOOTSTRAPS")
	env.Bool(fs, &cfg.Relay.DiscoveryEnabled, "discovery", false, "serve relay discovery endpoints and poll discovery peers", "DISCOVERY")
	env.String(fs, &cfg.Relay.IVNPConfigPath, "ivnp-config", "", "optional IVNP RouterConfig JSON file; {} uses in-memory defaults; requires discovery", "IVNP_CONFIG")

	env.Bool(fs, &cfg.Relay.HTTPRedirect.Enabled, "http-redirect-enabled", false, "enable HTTP redirects to the canonical HTTPS portal URL (not tenant hosts)", "HTTP_REDIRECT_ENABLED")
	env.String(fs, &cfg.Relay.HTTPRedirect.Addr, "http-redirect-addr", portal.DefaultHTTPRedirectAddr, "HTTP redirect listen address when enabled", "HTTP_REDIRECT_ADDR")
	env.Bool(fs, &cfg.Relay.HTTPRedirect.HSTS, "http-redirect-hsts", false, "include HSTS max-age=31536000 on redirects; browsers ignore HSTS received over HTTP", "HTTP_REDIRECT_HSTS")
	env.Int(fs, &cfg.Relay.SNIPort, "sni-port", 0, parsePortNumber, "local TCP SNI router listen port (0 follows the PORTAL_URL port when it names one, else 443)", "SNI_PORT")
	env.Bool(fs, &cfg.TrustProxyHeaders, "trust-proxy-headers", false, "trust X-Forwarded-* and X-Real-IP headers from trusted proxies", "TRUST_PROXY_HEADERS")
	env.String(fs, &cfg.TrustedProxyCIDRs, "trusted-proxy-cidrs", "", "explicit trusted proxy CIDR allowlist for forwarded headers, comma-separated; empty trusts no proxies", "TRUSTED_PROXY_CIDRS")
	env.String(fs, &cfg.TunnelSourceCIDRs, "tunnel-source-cidrs", "", "networks that may register tunnels, comma-separated CIDRs; empty allows every network", "TUNNEL_SOURCE_CIDRS")

	env.Bool(fs, &cfg.UDPEnabled, "udp-enabled", false, "enable UDP relay transport; requires a valid --min-port/--max-port range", "UDP_ENABLED")
	env.Bool(fs, &cfg.TCPEnabled, "tcp-enabled", false, "enable raw TCP port transport; requires a valid --min-port/--max-port range", "TCP_ENABLED")
	env.String(fs, &cfg.ApprovalMode, "approval-mode", string(policy.ModeAuto), "initial lease approval mode (auto|manual); a mode saved in policy.json wins", "APPROVAL_MODE")
	env.Int(fs, &cfg.Relay.DefaultIdentityBPS, "default-identity-bps", types.DefaultIdentityBPS, nil, "default stream bytes per second per service identity; individual admin limits override it (0=unlimited)", "DEFAULT_IDENTITY_BPS")
	env.Int(fs, &cfg.Relay.UnapprovedLeasesPerSource, "unapproved-leases-per-source", 64, nil, "leases one source IP can hold while they are not routable (0=unlimited)", "UNAPPROVED_LEASES_PER_SOURCE")
	env.Int(fs, &cfg.Relay.MinPort, "min-port", 0, parseOptionalPortNumber, "inclusive minimum lease port shared by UDP and raw TCP transports (0=disabled)", "MIN_PORT")
	env.Int(fs, &cfg.Relay.MaxPort, "max-port", 0, parseOptionalPortNumber, "inclusive maximum lease port shared by UDP and raw TCP transports (0=disabled)", "MAX_PORT")

	env.String(fs, &cfg.AdminToken, "admin-token", "", "admin bearer token for relay admin and policy APIs", "ADMIN_TOKEN")
	env.Bool(fs, &cfg.PprofEnabled, "pprof-enabled", false, "enable pprof diagnostics HTTP server", "PPROF_ENABLED")
	env.String(fs, &cfg.PprofListenAddr, "pprof-addr", DefaultPprofListenAddr, "pprof diagnostics listen address when enabled", "PPROF_ADDR")
	env.Bool(fs, &cfg.X402Enabled, "x402-enabled", false, "enable relay-owned Sui x402 facilitator endpoints under /api/x402 for future control-plane payments", "X402_ENABLED")
	env.Bool(fs, &cfg.X402Testnet, "x402-testnet", false, "use Sui testnet for relay-owned x402 facilitator payments", "X402_TESTNET")
	env.String(fs, &cfg.X402PayTo, "x402-pay-to", "", "Sui payment recipient address for relay-owned control-plane x402 resources", "X402_PAY_TO")

	env.String(fs, &cfg.Relay.ACME.CADirURL, "acme-ca-dir-url", "", "ACME CA directory URL (https) for managed certificate issuance; the CA must not require External Account Binding; defaults to Let's Encrypt production when empty", "ACME_CA_DIR_URL")
	env.String(fs, &cfg.Relay.ACME.DNSProvider, "acme-dns-provider", "", "DNS provider for managed DNS-01 and ENS gasless DNSSEC/TXT automation (embedded|cloudflare|gcloud|hetzner|njalla|route53|vultr); defaults to embedded without API credentials", "ACME_DNS_PROVIDER")
	env.Bool(fs, &cfg.Relay.ACME.ENSGaslessEnabled, "ens-gasless-enabled", false, "enable ENS gasless DNS import automation for the managed DNS zone and lease hostnames", "ENS_GASLESS_ENABLED")
	env.Int(fs, &cfg.Relay.ACME.EmbeddedDNSPort, "embedded-dns-port", 53, parsePortNumber, "listen port for the embedded authoritative DNS server (the default DNS provider); requires a one-time NS delegation of the base domain and open 53/tcp+udp", "EMBEDDED_DNS_PORT")
	env.String(fs, &cfg.Relay.ACME.CloudflareToken, "cloudflare-token", "", "Cloudflare DNS API token for DNS automation (required when acme-dns-provider=cloudflare)", "CLOUDFLARE_TOKEN")
	env.String(fs, &cfg.Relay.ACME.GCPProjectID, "gcp-project-id", "", "Google Cloud project id for Cloud DNS automation; auto-detected from ADC or GCE metadata when omitted", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCE_PROJECT")
	env.String(fs, &cfg.Relay.ACME.GCPManagedZone, "gcp-managed-zone", "", "explicit Google Cloud DNS managed zone name or numeric ID override", "GCP_MANAGED_ZONE", "GCP_ZONE", "GCE_ZONE_ID")
	env.String(fs, &cfg.Relay.ACME.HetznerAPIToken, "hetzner-api-token", "", "Hetzner Cloud API token for DNS automation (required when acme-dns-provider=hetzner)", "HETZNER_API_TOKEN", "HCLOUD_TOKEN")
	env.String(fs, &cfg.Relay.ACME.AWSAccessKeyID, "aws-access-key-id", "", "AWS access key ID for Route53 static credentials; uses the default AWS credential chain when omitted", "AWS_ACCESS_KEY_ID")
	env.String(fs, &cfg.Relay.ACME.AWSSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key for Route53 static credentials", "AWS_SECRET_ACCESS_KEY")
	env.String(fs, &cfg.Relay.ACME.AWSSessionToken, "aws-session-token", "", "AWS session token for Route53 temporary credentials", "AWS_SESSION_TOKEN")
	env.String(fs, &cfg.Relay.ACME.AWSRegion, "aws-region", "", "AWS region for Route53 and Route53-backed DNS-01; defaults to us-east-1 when unset", "AWS_REGION", "AWS_DEFAULT_REGION")
	env.String(fs, &cfg.Relay.ACME.AWSHostedZoneID, "aws-hosted-zone-id", "", "explicit Route53 hosted zone ID override", "AWS_HOSTED_ZONE_ID")
	env.String(fs, &cfg.Relay.ACME.AWSKMSKeyARN, "aws-dnssec-kms-key-arn", "", "AWS KMS key ARN used to create a Route53 DNSSEC key-signing key when needed", "AWS_DNSSEC_KMS_KEY_ARN")
	env.String(fs, &cfg.Relay.ACME.VultrAPIKey, "vultr-api-key", "", "Vultr API key for DNS automation (required when acme-dns-provider=vultr)", "VULTR_API_KEY")
	env.String(fs, &cfg.Relay.ACME.NjallaToken, "njalla-token", "", "Njalla API token for DNS automation (required when acme-dns-provider=njalla)", "NJALLA_TOKEN")
}

func runServeCommand(args []string) error {
	cfg, env, err := resolveAppConfig(args, os.Environ())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ingress, x402Settings, err := prepareAppConfig(&cfg, env.Issues)
	if err != nil {
		return err
	}

	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("state_dir", cfg.Relay.StateDir).
		Int("sni_port", cfg.Relay.SNIPort).
		Msg("starting relay server")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	return runServer(ctx, cfg, ingress, x402Settings)
}

func runServer(ctx context.Context, cfg appConfig, ingress *policy.Ingress, x402Settings x402FacilitatorSettings) error {
	// This application always serves /sdk/domain by composing facilitator metadata
	// onto server.DomainReport(), whether payments are enabled or not.
	cfg.Relay.ApplicationOwnsDomainReport = true
	server, err := portal.NewServer(cfg.Relay)
	if err != nil {
		return fmt.Errorf("create relay server: %w", err)
	}
	policies := policy.NewStore()
	policyPath := filepath.Join(cfg.Relay.StateDir, types.RelayPolicyFilename)
	initialPolicy := types.PolicySettings{
		ApprovalMode: cfg.ApprovalMode,
		UDP:          types.PolicyPortSettings{Enabled: cfg.UDPEnabled},
		TCPPort:      types.PolicyPortSettings{Enabled: cfg.TCPEnabled},
	}
	relayAPI, err := NewRelayAPI(server, policies, ingress, policyPath, cfg.AdminToken, cfg.FrontendDir, initialPolicy)
	if err != nil {
		return fmt.Errorf("create relay api: %w", err)
	}
	// Any admin write on an auto relay saves that mode, and a saved mode wins.
	// Only this direction warns, because it leaves a private relay open.
	if policy.Mode(cfg.ApprovalMode) == policy.ModeManual && policies.Snapshot().Mode() == policy.ModeAuto {
		log.Warn().Str("policy_path", policyPath).Msg("approval mode manual is ignored: policy.json saves auto, so every lease is approved; set the mode with the admin API")
	}

	appRoutes := relayAPI.Handler()
	if err := mountRelayRoutes(x402Settings, server, appRoutes); err != nil {
		return err
	}
	// The default relay owns the Admin, x402 and frontend control routes.
	// Embedders' application fallback handlers retain their own body limits.
	base := policy.ControlBodyHandler(appRoutes)
	handler := policy.Mux(server, base, ingress,
		policy.NewSourceLimiter(cfg.PreAuth.SourcePerMinute, cfg.PreAuth.SourceBurst, cfg.PreAuth.GlobalPerMinute, cfg.PreAuth.GlobalBurst),
		policies, cfg.PreAuth)
	handler = relayAPI.metrics.instrument(handler)
	if !cfg.PprofEnabled {
		return server.Serve(ctx, handler)
	}

	bound, stopPprof, pprofErrs, err := startPprofServer(ctx, normalizePprofAddr(cfg.PprofListenAddr))
	if err != nil {
		return err
	}
	log.Info().Str("pprof_addr", hostPortOrLoopback(bound.String())).Msg("starting pprof server")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	relayResult := make(chan error, 1)
	go func() {
		relayResult <- server.Serve(runCtx, handler)
	}()

	var serveErr error
	select {
	case serveErr = <-relayResult:
	case err := <-pprofErrs:
		serveErr = fmt.Errorf("serve pprof: %w", err)
		cancel()
		relayErr := <-relayResult
		serveErr = errors.Join(serveErr, relayErr)
	}
	cancel()

	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	if err := stopPprof(shutdownCtx); err != nil {
		log.Warn().Err(err).Msg("shutdown pprof server")
	}
	stop()
	return serveErr
}

// x402FacilitatorSettings is the resolved relay-owned x402 facilitator
// configuration. portal.Server knows nothing about payments: this application
// validates the flags and mounts the facilitator itself.
type x402FacilitatorSettings struct {
	Enabled bool
	Testnet bool
	PayTo   string
}

// resolveX402Facilitator resolves the relay-owned x402 flags. An enabled
// facilitator without a payment recipient would advertise payments nothing
// can settle, so it fails resolution instead of booting unusable. The
// recipient must normalize to a valid Sui address: it is published verbatim
// in the /sdk/domain facilitator metadata.
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

// Relay-owned x402 control-plane mount point and its supported listing path.
const (
	pathX402Facilitator = "/api/x402"
	x402SupportedPath   = pathX402Facilitator + "/supported"
)

// x402FacilitatorInfo is the application-local facilitator metadata composed
// onto the domain report.
type x402FacilitatorInfo struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url,omitempty"`
	Network      string `json:"network,omitempty"`
	NetworkName  string `json:"network_name,omitempty"`
	SupportedURL string `json:"supported_url,omitempty"`
	PayTo        string `json:"pay_to,omitempty"`
}

// domainResponse is the relay's /sdk/domain payload: the x402-blind core report
// extended with application-local facilitator metadata. The x402 key stays on
// the wire (zero value marshals as {"enabled":false}) so disabled deployments
// keep today's shape.
type domainResponse struct {
	types.DomainResponse
	X402 x402FacilitatorInfo `json:"x402"`
}

// mountRelayRoutes adds the relay-owned x402 facilitator to the application
// route table when payments are enabled; the facilitator is served at
// /api/x402. The application always serves /sdk/domain (the relay hands the
// path over via ServerConfig.ApplicationOwnsDomainReport) by composing the
// facilitator metadata onto server.DomainReport().
func mountRelayRoutes(settings x402FacilitatorSettings, server *portal.Server, mux *http.ServeMux) error {
	network := "sui:mainnet"
	if settings.Testnet {
		network = "sui:testnet"
	}

	if settings.Enabled {
		// Portal payments settle only Sui USDC (docs/src/routes/self-hosting),
		// so the facilitator allowlist is pinned to the network's USDC asset;
		// upstream default options would allowlist every gasless stablecoin.
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

func runHelpCommand(args []string) error {
	switch len(args) {
	case 0:
		printRootUsage(os.Stdout)
		return nil
	case 1:
		switch strings.TrimSpace(args[0]) {
		case "", "help", "-h", "--help", "serve":
			printRootUsage(os.Stdout)
			return nil
		default:
			printRootUsage(os.Stderr)
			return fmt.Errorf("unknown help topic %q", strings.TrimSpace(args[0]))
		}
	default:
		printRootUsage(os.Stderr)
		return errOnlyOneHelpTopicSupported
	}
}

func printRootUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{
			"relay-server [flags]",
			"relay-server serve [flags]",
			"relay-server help",
		},
		[]string{
			"relay-server",
			"relay-server serve",
			"relay-server --portal-url https://portal.example.com",
			"relay-server --discovery --bootstraps https://bootstrap.example.com",
			"relay-server --udp-enabled --min-port 40000 --max-port 40099",
			"relay-server help",
		},
	)
	fs := cli.NewFlagSet("relay-server", nil)
	registerAppFlags(fs, &appConfig{}, cli.NewEnv(nil))
	cli.WriteFlagDefaults(w, fs)
	cli.WriteHelpSection(w, "Loopback", []string{
		"relay-server --portal-url https://127.0.0.1:8443",
		"portal expose 127.0.0.1:8080 --relays https://127.0.0.1:8443 --discovery=false",
	})
	cli.WriteHelpSection(w, "Ready", []string{
		"After portal expose succeeds, it logs a line starting with: service ready at",
	})
}
