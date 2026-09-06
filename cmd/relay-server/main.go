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

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/acme"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	portalx402 "github.com/gosuda/portal-tunnel/v2/portal/x402"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"":       runServeCommand,
		"serve":  runServeCommand,
		"config": runConfigCommand,
		"help":   runHelpCommand,
	}); err != nil {
		log.Error().Err(err).Msg("execute root command")
		os.Exit(1)
	}
}

type relayServerConfig struct {
	PortalURL          string
	FrontendDir        string
	IdentityPath       string
	Bootstraps         string
	DiscoveryEnabled   bool
	WireGuardPort      int
	HTTPRedirect       types.HTTPRedirectConfig
	APIPort            int
	SNIPort            int
	TrustProxyHeaders  bool
	TrustedProxyCIDRs  string
	UDPEnabled         bool
	TCPEnabled         bool
	LandingPageEnabled bool
	MinPort            int
	MaxPort            int
	AdminToken         string
	PProfEnabled       bool
	PProfAddr          string
	X402Enabled        bool
	X402Testnet        bool
	X402PayTo          string

	ACMEDNSProvider    string
	ENSGaslessEnabled  bool
	EmbeddedDNSPort    int
	CloudflareToken    string
	GCPProjectID       string
	GCPManagedZone     string
	HetznerAPIToken    string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	AWSRegion          string
	AWSHostedZoneID    string
	AWSDNSSECKMSKeyARN string
	VultrAPIKey        string
	NjallaToken        string
}

// resolveRelayServerConfig registers every flag and resolves it against the
// process environment. The config subcommand reuses it so that inspecting a
// deployment and running it read the same definitions.
func resolveRelayServerConfig(args []string) (relayServerConfig, error) {
	// Registration records into a process-global registry, so start from empty:
	// the config subcommand loads an env file and resolves again, and issues
	// from an earlier pass must not fail the current one.
	utils.ResetEnvRegistry()

	cfg := relayServerConfig{}
	fs := utils.NewFlagSet("relay-server", printRootUsage)
	registerRelayServerFlags(fs, &cfg)

	if err := utils.ParseFlagSet(fs, args, printRootUsage); err != nil {
		return relayServerConfig{}, err
	}
	if err := utils.RequireNoArgs(fs.Args(), "relay-server"); err != nil {
		printRootUsage(os.Stderr)
		return relayServerConfig{}, err
	}
	cfg.IdentityPath = identity.ResolveRelayStateDir(cfg.IdentityPath)
	return cfg, nil
}

func registerRelayServerFlags(fs *flag.FlagSet, cfg *relayServerConfig) {
	utils.StringFlagEnv(fs, &cfg.PortalURL, "portal-url", "https://localhost", "portal base URL", "PORTAL_URL")
	utils.StringFlagEnv(fs, &cfg.FrontendDir, "frontend-dir", "", "custom SPA directory containing index.html; embedded frontend is used when empty", "PORTAL_FRONTEND_DIR")
	utils.StringFlagEnv(fs, &cfg.IdentityPath, "identity-path", "./.portal-certs", "directory path for relay identity, policy state, and keyless materials", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &cfg.Bootstraps, "bootstraps", "", "bootstrap relay API URLs; merged with bootstrap relays when discovery is enabled", "BOOTSTRAPS")
	utils.BoolFlagEnv(fs, &cfg.DiscoveryEnabled, "discovery", false, "serve relay discovery endpoints and poll discovery peers", "DISCOVERY")
	utils.IntFlagEnv(fs, &cfg.WireGuardPort, "wireguard-port", overlay.DefaultListenPort, utils.ParsePortNumber, "public and listen UDP port for relay overlay", "WIREGUARD_PORT")

	utils.BoolFlagEnv(fs, &cfg.HTTPRedirect.Enabled, "http-redirect-enabled", false, "enable HTTP redirects to the canonical HTTPS portal URL (not tenant hosts)", types.HTTPRedirectEnabledEnv)
	utils.StringFlagEnv(fs, &cfg.HTTPRedirect.Addr, "http-redirect-addr", types.DefaultHTTPRedirectAddr, "HTTP redirect listen address when enabled", "HTTP_REDIRECT_ADDR")
	utils.BoolFlagEnv(fs, &cfg.HTTPRedirect.HSTS, "http-redirect-hsts", false, "include HSTS max-age=31536000 on redirects; browsers ignore HSTS received over HTTP", "HTTP_REDIRECT_HSTS")
	utils.IntFlagEnv(fs, &cfg.APIPort, "api-port", 4017, utils.ParsePortNumber, "Admin/API server port", "API_PORT")
	utils.IntFlagEnv(fs, &cfg.SNIPort, "sni-port", 443, utils.ParsePortNumber, "TCP SNI router port number", "SNI_PORT")
	utils.BoolFlagEnv(fs, &cfg.TrustProxyHeaders, "trust-proxy-headers", false, "trust X-Forwarded-* and X-Real-IP headers from trusted proxies", "TRUST_PROXY_HEADERS")
	utils.StringFlagEnv(fs, &cfg.TrustedProxyCIDRs, "trusted-proxy-cidrs", "", "trusted proxy CIDR allowlist for forwarded headers, comma-separated; defaults to private/loopback proxy ranges when trust-proxy-headers is enabled", "TRUSTED_PROXY_CIDRS")

	utils.BoolFlagEnv(fs, &cfg.UDPEnabled, "udp-enabled", false, "enable UDP relay transport; requires a valid --min-port/--max-port range", "UDP_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.TCPEnabled, "tcp-enabled", false, "enable raw TCP port transport; requires a valid --min-port/--max-port range", "TCP_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.LandingPageEnabled, "landing-page-enabled", false, "show the dashboard landing page", "LANDING_PAGE_ENABLED")
	utils.IntFlagEnv(fs, &cfg.MinPort, "min-port", 0, utils.ParseOptionalPortNumber, "inclusive minimum lease port shared by UDP and raw TCP transports (0=disabled)", "MIN_PORT")
	utils.IntFlagEnv(fs, &cfg.MaxPort, "max-port", 0, utils.ParseOptionalPortNumber, "inclusive maximum lease port shared by UDP and raw TCP transports (0=disabled)", "MAX_PORT")

	utils.StringFlagEnv(fs, &cfg.AdminToken, "admin-token", "", "admin bearer token for relay admin and policy APIs", "ADMIN_TOKEN")
	utils.BoolFlagEnv(fs, &cfg.PProfEnabled, "pprof-enabled", false, "enable pprof diagnostics HTTP server", "PPROF_ENABLED")
	utils.StringFlagEnv(fs, &cfg.PProfAddr, "pprof-addr", portal.DefaultPProfListenAddr, "pprof diagnostics listen address when enabled", "PPROF_ADDR")
	utils.BoolFlagEnv(fs, &cfg.X402Enabled, "x402-enabled", false, "enable relay-owned Sui x402 facilitator endpoints under /api/x402 for future control-plane payments", "X402_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.X402Testnet, "x402-testnet", false, "use Sui testnet for relay-owned x402 facilitator payments", "X402_TESTNET")
	utils.StringFlagEnv(fs, &cfg.X402PayTo, "x402-pay-to", "", "Sui payment recipient address for relay-owned control-plane x402 resources", "X402_PAY_TO")

	utils.StringFlagEnv(fs, &cfg.ACMEDNSProvider, "acme-dns-provider", "", "DNS provider for managed DNS-01/A-record sync, ECH HTTPS records, and ENS gasless DNSSEC/TXT automation (embedded|cloudflare|gcloud|hetzner|njalla|route53|vultr); defaults to embedded without API credentials; external managed providers are deprecated until removal in a future major release", "ACME_DNS_PROVIDER")
	utils.BoolFlagEnv(fs, &cfg.ENSGaslessEnabled, "ens-gasless-enabled", false, "enable ENS gasless DNS import automation for the managed DNS zone and lease hostnames", "ENS_GASLESS_ENABLED")
	utils.IntFlagEnv(fs, &cfg.EmbeddedDNSPort, "embedded-dns-port", 53, utils.ParsePortNumber, "listen port for the embedded authoritative DNS server (the default DNS provider); requires a one-time NS delegation of the base domain and open 53/tcp+udp", "EMBEDDED_DNS_PORT")
	utils.StringFlagEnv(fs, &cfg.CloudflareToken, "cloudflare-token", "", "Cloudflare DNS API token for DNS automation (required when acme-dns-provider=cloudflare)", "CLOUDFLARE_TOKEN")
	utils.StringFlagEnv(fs, &cfg.GCPProjectID, "gcp-project-id", "", "Google Cloud project id for Cloud DNS automation; auto-detected from ADC or GCE metadata when omitted", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCE_PROJECT")
	utils.StringFlagEnv(fs, &cfg.GCPManagedZone, "gcp-managed-zone", "", "explicit Google Cloud DNS managed zone name or numeric ID override", "GCP_MANAGED_ZONE", "GCP_ZONE", "GCE_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.HetznerAPIToken, "hetzner-api-token", "", "Hetzner Cloud API token for DNS automation (required when acme-dns-provider=hetzner)", "HETZNER_API_TOKEN", "HCLOUD_TOKEN")
	utils.StringFlagEnv(fs, &cfg.AWSAccessKeyID, "aws-access-key-id", "", "AWS access key ID for Route53 static credentials; uses the default AWS credential chain when omitted", "AWS_ACCESS_KEY_ID")
	utils.StringFlagEnv(fs, &cfg.AWSSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key for Route53 static credentials", "AWS_SECRET_ACCESS_KEY")
	utils.StringFlagEnv(fs, &cfg.AWSSessionToken, "aws-session-token", "", "AWS session token for Route53 temporary credentials", "AWS_SESSION_TOKEN")
	utils.StringFlagEnv(fs, &cfg.AWSRegion, "aws-region", "", "AWS region for Route53 and Route53-backed DNS-01; defaults to us-east-1 when unset", "AWS_REGION", "AWS_DEFAULT_REGION")
	utils.StringFlagEnv(fs, &cfg.AWSHostedZoneID, "aws-hosted-zone-id", "", "explicit Route53 hosted zone ID override", "AWS_HOSTED_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.AWSDNSSECKMSKeyARN, "aws-dnssec-kms-key-arn", "", "AWS KMS key ARN used to create a Route53 DNSSEC key-signing key when needed", "AWS_DNSSEC_KMS_KEY_ARN")
	utils.StringFlagEnv(fs, &cfg.VultrAPIKey, "vultr-api-key", "", "Vultr API key for DNS automation (required when acme-dns-provider=vultr)", "VULTR_API_KEY")
	utils.StringFlagEnv(fs, &cfg.NjallaToken, "njalla-token", "", "Njalla API token for DNS automation (required when acme-dns-provider=njalla)", "NJALLA_TOKEN")
}

func runServeCommand(args []string) error {
	cfg, err := resolveRelayServerConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	// A value that could not be parsed is always a mistake. Starting anyway is
	// how a deployment ends up running with a setting nobody reads.
	if err := envIssueError(); err != nil {
		return err
	}

	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("portal_url", cfg.PortalURL).
		Str("identity_path", cfg.IdentityPath).
		Int("api_port", cfg.APIPort).
		Int("sni_port", cfg.SNIPort).
		Msg("starting relay server")

	// Report each capability with the setting that produced it, so a feature
	// that was switched off is distinguishable from one that cannot run.
	logFeatureReport(evaluateFeatures(cfg))

	ctx, stop := utils.SignalContext()
	defer stop()

	return runServer(ctx, cfg)
}

func runServer(ctx context.Context, cfg relayServerConfig) error {
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:         cfg.PortalURL,
		HTTPRedirect:      cfg.HTTPRedirect,
		IdentityPath:      cfg.IdentityPath,
		Bootstraps:        utils.SplitCSV(cfg.Bootstraps),
		DiscoveryEnabled:  cfg.DiscoveryEnabled,
		WireGuardPort:     cfg.WireGuardPort,
		APIPort:           cfg.APIPort,
		SNIPort:           cfg.SNIPort,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		UDPEnabled:        cfg.UDPEnabled,
		TCPEnabled:        cfg.TCPEnabled,
		MinPort:           cfg.MinPort,
		MaxPort:           cfg.MaxPort,
		PProfEnabled:      cfg.PProfEnabled,
		PProfListenAddr:   cfg.PProfAddr,
		X402Enabled:       cfg.X402Enabled,
		X402Testnet:       cfg.X402Testnet,
		X402PayTo:         cfg.X402PayTo,
		ACME: acme.Config{
			KeyDir:             cfg.IdentityPath,
			DNSProvider:        cfg.ACMEDNSProvider,
			ENSGaslessEnabled:  cfg.ENSGaslessEnabled,
			EmbeddedDNSPort:    cfg.EmbeddedDNSPort,
			CloudflareToken:    cfg.CloudflareToken,
			GCPProjectID:       cfg.GCPProjectID,
			GCPManagedZone:     cfg.GCPManagedZone,
			HetznerAPIToken:    cfg.HetznerAPIToken,
			AWSAccessKeyID:     cfg.AWSAccessKeyID,
			AWSSecretAccessKey: cfg.AWSSecretAccessKey,
			AWSSessionToken:    cfg.AWSSessionToken,
			AWSRegion:          cfg.AWSRegion,
			AWSHostedZoneID:    cfg.AWSHostedZoneID,
			AWSKMSKeyARN:       cfg.AWSDNSSECKMSKeyARN,
			VultrAPIKey:        cfg.VultrAPIKey,
			NjallaToken:        cfg.NjallaToken,
		},
	})
	if err != nil {
		return fmt.Errorf("create relay server: %w", err)
	}

	relayAPI, err := NewRelayAPI(server, cfg.IdentityPath, cfg.AdminToken, cfg.FrontendDir, cfg.LandingPageEnabled)
	if err != nil {
		return fmt.Errorf("create relay api: %w", err)
	}

	apiMux := relayAPI.Handler()
	if cfg.X402Enabled {
		x402Network := portalx402.Network(cfg.X402Testnet)
		if err := portalx402.MountFacilitator(apiMux, portalx402.FacilitatorConfig{
			Testnet: cfg.X402Testnet,
		}); err != nil {
			return fmt.Errorf("mount x402 facilitator: %w", err)
		}
		log.Info().
			Str("path", types.PathX402Facilitator).
			Str("network", x402Network).
			Msg("relay-owned x402 facilitator enabled")
	}

	if err := server.Start(ctx, apiMux); err != nil {
		return fmt.Errorf("start relay server: %w", err)
	}

	return server.Wait()
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
		return errors.New("only one help topic is supported")
	}
}

func printRootUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
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
	fs := utils.NewFlagSet("relay-server", nil)
	registerRelayServerFlags(fs, &relayServerConfig{})
	utils.WriteFlagDefaults(w, fs)
	utils.WriteHelpSection(w, "Loopback", []string{
		"relay-server --portal-url https://127.0.0.1:4017 --api-port 4017 --sni-port 8443",
		"portal expose 127.0.0.1:8080 --relays https://127.0.0.1:4017 --discovery=false",
	})
	utils.WriteHelpSection(w, "Ready", []string{
		"After portal expose succeeds, it logs a line starting with: service ready at",
	})
}
