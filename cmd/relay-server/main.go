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
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"":      runServeCommand,
		"serve": runServeCommand,
		"help":  runHelpCommand,
	}); err != nil {
		log.Error().Err(err).Msg("execute root command")
		os.Exit(1)
	}
}

type relayServerConfig struct {
	PortalURL          string
	IdentityPath       string
	Bootstraps         string
	DiscoveryEnabled   bool
	WireGuardPort      int
	APIPort            int
	SNIPort            int
	TrustProxyHeaders  bool
	TrustedProxyCIDRs  string
	UDPEnabled         bool
	TCPEnabled         bool
	MinPort            int
	MaxPort            int
	AdminWallets       string
	LandingPageEnabled bool
	HeadlessShellURL   string
	PProfEnabled       bool
	PProfAddr          string

	ACMEDNSProvider    string
	ENSGaslessEnabled  bool
	CloudflareToken    string
	GCPProjectID       string
	GCPManagedZone     string
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	AWSRegion          string
	AWSHostedZoneID    string
	AWSDNSSECKMSKeyARN string
}

func runServeCommand(args []string) error {
	cfg := relayServerConfig{}
	fs := utils.NewFlagSet("relay-server", printRootUsage)

	utils.StringFlagEnv(fs, &cfg.PortalURL, "portal-url", "https://localhost:4017", "portal base URL", "PORTAL_URL")
	utils.StringFlagEnv(fs, &cfg.IdentityPath, "identity-path", "./.portal-certs", "directory path for relay identity, admin state, and keyless materials", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &cfg.Bootstraps, "bootstraps", "", "bootstrap relay API URLs; merged with bootstrap relays when discovery is enabled", "BOOTSTRAPS")
	utils.BoolFlagEnv(fs, &cfg.DiscoveryEnabled, "discovery", false, "serve relay discovery endpoints and poll discovery peers", "DISCOVERY")
	utils.IntFlagEnv(fs, &cfg.WireGuardPort, "wireguard-port", overlay.DefaultListenPort, utils.ParsePortNumber, "public and listen UDP port for relay overlay", "WIREGUARD_PORT")

	utils.IntFlagEnv(fs, &cfg.APIPort, "api-port", 4017, utils.ParsePortNumber, "Admin/API server port", "API_PORT")
	utils.IntFlagEnv(fs, &cfg.SNIPort, "sni-port", 443, utils.ParsePortNumber, "TCP SNI router port number", "SNI_PORT")
	utils.BoolFlagEnv(fs, &cfg.TrustProxyHeaders, "trust-proxy-headers", false, "trust X-Forwarded-* and X-Real-IP headers from trusted proxies", "TRUST_PROXY_HEADERS")
	utils.StringFlagEnv(fs, &cfg.TrustedProxyCIDRs, "trusted-proxy-cidrs", "", "trusted proxy CIDR allowlist for forwarded headers, comma-separated; defaults to private/loopback proxy ranges when trust-proxy-headers is enabled", "TRUSTED_PROXY_CIDRS")

	utils.BoolFlagEnv(fs, &cfg.UDPEnabled, "udp-enabled", false, "enable UDP relay transport; requires a valid --min-port/--max-port range", "UDP_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.TCPEnabled, "tcp-enabled", false, "enable raw TCP port transport; requires a valid --min-port/--max-port range", "TCP_ENABLED")
	utils.IntFlagEnv(fs, &cfg.MinPort, "min-port", 0, utils.ParseOptionalPortNumber, "inclusive minimum lease port shared by UDP and raw TCP transports (0=disabled)", "MIN_PORT")
	utils.IntFlagEnv(fs, &cfg.MaxPort, "max-port", 0, utils.ParseOptionalPortNumber, "inclusive maximum lease port shared by UDP and raw TCP transports (0=disabled)", "MAX_PORT")

	utils.StringFlagEnv(fs, &cfg.AdminWallets, "admin-wallets", "", "admin wallet address allowlist, comma-separated; relay identity address is always allowed", "ADMIN_WALLETS")
	utils.BoolFlagEnv(fs, &cfg.LandingPageEnabled, "landing-page-enabled", false, "enable landing page by default when no admin setting has been saved yet", "LANDING_PAGE_ENABLED")
	utils.StringFlagEnv(fs, &cfg.HeadlessShellURL, "headless-shell-url", "", "headless Chrome CDP WebSocket URL for thumbnail generation (e.g. ws://headless-shell:9222)", "HEADLESS_SHELL_URL")
	utils.BoolFlagEnv(fs, &cfg.PProfEnabled, "pprof-enabled", false, "enable pprof diagnostics HTTP server", "PPROF_ENABLED")
	utils.StringFlagEnv(fs, &cfg.PProfAddr, "pprof-addr", portal.DefaultPProfListenAddr, "pprof diagnostics listen address when enabled", "PPROF_ADDR")

	utils.StringFlagEnv(fs, &cfg.ACMEDNSProvider, "acme-dns-provider", "", "DNS provider for managed DNS-01/A-record sync, ECH HTTPS records, and ENS gasless DNSSEC/TXT automation (cloudflare|gcloud|route53); leave empty to use manual fullchain.pem/privatekey.pem from IDENTITY_PATH", "ACME_DNS_PROVIDER")
	utils.BoolFlagEnv(fs, &cfg.ENSGaslessEnabled, "ens-gasless-enabled", false, "enable ENS gasless DNS import automation for the managed DNS zone and lease hostnames", "ENS_GASLESS_ENABLED")
	utils.StringFlagEnv(fs, &cfg.CloudflareToken, "cloudflare-token", "", "Cloudflare DNS API token (required when acme-dns-provider=cloudflare)", "CLOUDFLARE_TOKEN")
	utils.StringFlagEnv(fs, &cfg.GCPProjectID, "gcp-project-id", "", "Google Cloud project id for Cloud DNS automation; auto-detected from ADC or GCE metadata when omitted", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCE_PROJECT")
	utils.StringFlagEnv(fs, &cfg.GCPManagedZone, "gcp-managed-zone", "", "explicit Google Cloud DNS managed zone name or numeric ID override", "GCP_MANAGED_ZONE", "GCP_ZONE", "GCE_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.AWSAccessKeyID, "aws-access-key-id", "", "AWS access key ID for Route53 static credentials; uses the default AWS credential chain when omitted", "AWS_ACCESS_KEY_ID")
	utils.StringFlagEnv(fs, &cfg.AWSSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key for Route53 static credentials", "AWS_SECRET_ACCESS_KEY")
	utils.StringFlagEnv(fs, &cfg.AWSSessionToken, "aws-session-token", "", "AWS session token for Route53 temporary credentials", "AWS_SESSION_TOKEN")
	utils.StringFlagEnv(fs, &cfg.AWSRegion, "aws-region", "", "AWS region for Route53 and Route53-backed DNS-01; defaults to us-east-1 when unset", "AWS_REGION", "AWS_DEFAULT_REGION")
	utils.StringFlagEnv(fs, &cfg.AWSHostedZoneID, "aws-hosted-zone-id", "", "explicit Route53 hosted zone ID override", "AWS_HOSTED_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.AWSDNSSECKMSKeyARN, "aws-dnssec-kms-key-arn", "", "AWS KMS key ARN used to create a Route53 DNSSEC key-signing key when needed", "AWS_DNSSEC_KMS_KEY_ARN")

	if err := utils.ParseFlagSet(fs, args, printRootUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "relay-server"); err != nil {
		printRootUsage(os.Stderr)
		return err
	}
	cfg.IdentityPath = identity.ResolveRelayStateDir(cfg.IdentityPath)

	log.Info().
		Str("release_version", types.ReleaseVersion).
		Str("portal_url", cfg.PortalURL).
		Str("identity_path", cfg.IdentityPath).
		Str("bootstraps", cfg.Bootstraps).
		Bool("discovery_enabled", cfg.DiscoveryEnabled).
		Int("wireguard_port", cfg.WireGuardPort).
		Int("api_port", cfg.APIPort).
		Int("sni_port", cfg.SNIPort).
		Bool("trust_proxy_headers", cfg.TrustProxyHeaders).
		Str("trusted_proxy_cidrs", cfg.TrustedProxyCIDRs).
		Bool("udp_enabled", cfg.UDPEnabled).
		Bool("tcp_enabled", cfg.TCPEnabled).
		Int("min_port", cfg.MinPort).
		Int("max_port", cfg.MaxPort).
		Bool("admin_wallets_configured", len(utils.SplitCSV(cfg.AdminWallets)) > 0).
		Bool("landing_page_enabled", cfg.LandingPageEnabled).
		Bool("headless_shell_enabled", strings.TrimSpace(cfg.HeadlessShellURL) != "").
		Bool("pprof_enabled", cfg.PProfEnabled).
		Str("pprof_addr", cfg.PProfAddr).
		Str("acme_dns_provider", cfg.ACMEDNSProvider).
		Bool("ens_gasless_enabled", cfg.ENSGaslessEnabled).
		Msg("configured relay server")

	ctx, stop := utils.SignalContext()
	defer stop()

	return runServer(ctx, cfg)
}

func runServer(ctx context.Context, cfg relayServerConfig) error {
	server, err := portal.NewServer(portal.ServerConfig{
		PortalURL:         cfg.PortalURL,
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
		ACME: acme.Config{
			KeyDir:             cfg.IdentityPath,
			DNSProvider:        cfg.ACMEDNSProvider,
			ENSGaslessEnabled:  cfg.ENSGaslessEnabled,
			CloudflareToken:    cfg.CloudflareToken,
			GCPProjectID:       cfg.GCPProjectID,
			GCPManagedZone:     cfg.GCPManagedZone,
			AWSAccessKeyID:     cfg.AWSAccessKeyID,
			AWSSecretAccessKey: cfg.AWSSecretAccessKey,
			AWSSessionToken:    cfg.AWSSessionToken,
			AWSRegion:          cfg.AWSRegion,
			AWSHostedZoneID:    cfg.AWSHostedZoneID,
			AWSKMSKeyARN:       cfg.AWSDNSSECKMSKeyARN,
		},
	})
	if err != nil {
		return fmt.Errorf("create relay server: %w", err)
	}

	frontend, err := NewFrontend(server, cfg.IdentityPath, cfg.LandingPageEnabled, cfg.HeadlessShellURL, utils.SplitCSV(cfg.AdminWallets))
	if err != nil {
		return fmt.Errorf("create frontend: %w", err)
	}
	defer frontend.Close()

	if err := server.Start(ctx, frontend.Handler()); err != nil {
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
			"relay-server --landing-page-enabled",
			"relay-server help",
		},
	)
}
