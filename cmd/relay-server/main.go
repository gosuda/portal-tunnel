package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
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

type appConfig struct {
	Relay              portal.ServerConfig
	FrontendDir        string
	LandingPageEnabled bool
	AdminToken         string
	Reputation         ReputationConfig
}

// resolveAppConfig registers every flag and resolves it against the
// process environment. The config subcommand reuses it so that inspecting a
// deployment and running it read the same definitions.
func resolveAppConfig(args []string) (appConfig, error) {
	// Registration records into a process-global registry, so start from empty:
	// the config subcommand loads an env file and resolves again, and issues
	// from an earlier pass must not fail the current one.
	utils.ResetEnvRegistry()

	cfg := appConfig{}
	fs := utils.NewFlagSet("relay-server", printRootUsage)
	registerAppFlags(fs, &cfg)

	if err := utils.ParseFlagSet(fs, args, printRootUsage); err != nil {
		return appConfig{}, err
	}
	if err := utils.RequireNoArgs(fs.Args(), "relay-server"); err != nil {
		printRootUsage(os.Stderr)
		return appConfig{}, err
	}
	cfg.Relay.StateDir = strings.TrimSpace(cfg.Relay.StateDir)
	return cfg, nil
}

func registerAppFlags(fs *flag.FlagSet, cfg *appConfig) {
	preAuthDefaults := policy.DefaultPreAuthConfig()
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.SourcePerMinute, "preauth-source-per-minute", preAuthDefaults.SourcePerMinute, nil, "per-source pre-auth units refilled per minute", "PREAUTH_SOURCE_PER_MINUTE")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.SourceBurst, "preauth-source-burst", preAuthDefaults.SourceBurst, nil, "per-source pre-auth burst units", "PREAUTH_SOURCE_BURST")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.GlobalPerMinute, "preauth-global-per-minute", preAuthDefaults.GlobalPerMinute, nil, "global pre-auth units refilled per minute", "PREAUTH_GLOBAL_PER_MINUTE")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.GlobalBurst, "preauth-global-burst", preAuthDefaults.GlobalBurst, nil, "global pre-auth burst units", "PREAUTH_GLOBAL_BURST")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.ChallengeCost, "preauth-challenge-cost", preAuthDefaults.ChallengeCost, nil, "pre-auth units per registration challenge", "PREAUTH_CHALLENGE_COST")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.AnnounceCost, "preauth-announce-cost", preAuthDefaults.AnnounceCost, nil, "pre-auth units per discovery announce", "PREAUTH_ANNOUNCE_COST")
	utils.IntFlagEnv(fs, &cfg.Relay.PreAuth.RegisterCost, "preauth-register-cost", preAuthDefaults.RegisterCost, nil, "pre-auth units per registration attempt", "PREAUTH_REGISTER_COST")

	utils.BoolFlagEnv(fs, &cfg.Relay.Cache.Enabled, "cache-enabled", true, "allow explicitly opted-in static exposures to use the relay disk cache", "CACHE_ENABLED")
	utils.IntFlagEnv(fs, &cfg.Relay.Cache.MaxBytes, "cache-max-bytes", 1<<30, nil, "maximum relay cached and staging payload bytes", "CACHE_MAX_BYTES")
	utils.DurationFlagEnv(fs, &cfg.Relay.Cache.MaxTTL, "cache-max-ttl", 24*time.Hour, "maximum offline cache lifetime after unregister or lease expiry", "CACHE_MAX_TTL")

	reputationDefaults := defaultReputationConfig()
	utils.IntFlagEnv(fs, &cfg.Reputation.MinTotal, "reputation-min-total", reputationDefaults.MinTotal, nil, "minimum total votes before the service warning can fire", "REPUTATION_MIN_TOTAL")
	utils.IntFlagEnv(fs, &cfg.Reputation.MinDown, "reputation-min-down", reputationDefaults.MinDown, nil, "minimum down votes before the service warning can fire", "REPUTATION_MIN_DOWN")
	utils.IntFlagEnv(fs, &cfg.Reputation.MinDownRatioPercent, "reputation-down-ratio-percent", reputationDefaults.MinDownRatioPercent, nil, "minimum down-vote ratio percent before the service warning can fire", "REPUTATION_DOWN_RATIO_PERCENT")
	utils.DurationFlagEnv(fs, &cfg.Reputation.Probation, "reputation-probation", reputationDefaults.Probation, "hostnames stay new and owner-key changes stay flagged for this long", "REPUTATION_PROBATION")
	utils.DurationFlagEnv(fs, &cfg.Reputation.Retention, "reputation-retention", reputationDefaults.Retention, "prune hostname reputation that has not appeared in the public lease set for this long", "REPUTATION_RETENTION")
	utils.IntFlagEnv(fs, &cfg.Reputation.VoteSourcePerMinute, "reputation-vote-per-minute", reputationDefaults.VoteSourcePerMinute, nil, "per-source reputation votes refilled per minute", "REPUTATION_VOTE_PER_MINUTE")
	utils.IntFlagEnv(fs, &cfg.Reputation.VoteSourceBurst, "reputation-vote-burst", reputationDefaults.VoteSourceBurst, nil, "per-source reputation vote burst", "REPUTATION_VOTE_BURST")
	utils.IntFlagEnv(fs, &cfg.Reputation.MaxVotersPerSource, "reputation-max-voters-per-source", reputationDefaults.MaxVotersPerSource, nil, "maximum voter IDs a single source may mint without a cookie; resets on restart", "REPUTATION_MAX_VOTERS_PER_SOURCE")
	utils.IntFlagEnv(fs, &cfg.Reputation.MaxVotersPerHostname, "reputation-max-voters-per-hostname", reputationDefaults.MaxVotersPerHostname, nil, "maximum distinct voters per hostname; new voters rejected with 429 when exhausted", "REPUTATION_MAX_VOTERS_PER_HOSTNAME")
	utils.IntFlagEnv(fs, &cfg.Reputation.MaxHostnames, "reputation-max-hostnames", reputationDefaults.MaxHostnames, nil, "relay-wide cap on hostnames with votes; oldest voteless is evicted when exceeded", "REPUTATION_MAX_HOSTNAMES")
	utils.IntFlagEnv(fs, &cfg.Reputation.MaxMintSources, "reputation-max-mint-sources", reputationDefaults.MaxMintSources, nil, "maximum distinct sources that may hold cookieless minted voter IDs; new sources beyond the cap get 429", "REPUTATION_MAX_MINT_SOURCES")
	utils.StringFlagEnv(fs, &cfg.Relay.PortalURL, "portal-url", "https://localhost", "portal base URL", "PORTAL_URL")
	utils.StringFlagEnv(fs, &cfg.FrontendDir, "frontend-dir", "", "custom SPA directory containing index.html; embedded frontend is used when empty", "PORTAL_FRONTEND_DIR")
	utils.StringFlagEnv(fs, &cfg.Relay.StateDir, "identity-path", "./.portal-certs", "directory path for relay identity, policy state, and keyless materials", "IDENTITY_PATH")
	utils.CSVFlagEnv(fs, &cfg.Relay.Bootstraps, "bootstraps", "", "bootstrap relay API URLs; merged with bootstrap relays when discovery is enabled", "BOOTSTRAPS")
	utils.BoolFlagEnv(fs, &cfg.Relay.DiscoveryEnabled, "discovery", false, "serve relay discovery endpoints and poll discovery peers", "DISCOVERY")
	utils.StringFlagEnv(fs, &cfg.Relay.IVNPConfigPath, "ivnp-config", "", "optional IVNP RouterConfig JSON file; {} uses in-memory defaults; requires discovery", "IVNP_CONFIG")

	utils.BoolFlagEnv(fs, &cfg.Relay.HTTPRedirect.Enabled, "http-redirect-enabled", false, "enable HTTP redirects to the canonical HTTPS portal URL (not tenant hosts)", types.HTTPRedirectEnabledEnv)
	utils.StringFlagEnv(fs, &cfg.Relay.HTTPRedirect.Addr, "http-redirect-addr", types.DefaultHTTPRedirectAddr, "HTTP redirect listen address when enabled", "HTTP_REDIRECT_ADDR")
	utils.BoolFlagEnv(fs, &cfg.Relay.HTTPRedirect.HSTS, "http-redirect-hsts", false, "include HSTS max-age=31536000 on redirects; browsers ignore HSTS received over HTTP", "HTTP_REDIRECT_HSTS")
	utils.IntFlagEnv(fs, &cfg.Relay.APIPort, "api-port", 4017, utils.ParsePortNumber, "Admin/API server port", "API_PORT")
	utils.IntFlagEnv(fs, &cfg.Relay.SNIPort, "sni-port", 0, utils.ParsePortNumber, "local TCP SNI router listen port (0 follows the PORTAL_URL port when it names one, else 443)", "SNI_PORT")
	utils.BoolFlagEnv(fs, &cfg.Relay.TrustProxyHeaders, "trust-proxy-headers", false, "trust X-Forwarded-* and X-Real-IP headers from trusted proxies", "TRUST_PROXY_HEADERS")
	utils.StringFlagEnv(fs, &cfg.Relay.TrustedProxyCIDRs, "trusted-proxy-cidrs", "", "explicit trusted proxy CIDR allowlist for forwarded headers, comma-separated; empty trusts no proxies", "TRUSTED_PROXY_CIDRS")

	utils.BoolFlagEnv(fs, &cfg.Relay.UDPEnabled, "udp-enabled", false, "enable UDP relay transport; requires a valid --min-port/--max-port range", "UDP_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.Relay.TCPEnabled, "tcp-enabled", false, "enable raw TCP port transport; requires a valid --min-port/--max-port range", "TCP_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.LandingPageEnabled, "landing-page-enabled", false, "show the dashboard landing page", "LANDING_PAGE_ENABLED")
	utils.IntFlagEnv(fs, &cfg.Relay.MinPort, "min-port", 0, utils.ParseOptionalPortNumber, "inclusive minimum lease port shared by UDP and raw TCP transports (0=disabled)", "MIN_PORT")
	utils.IntFlagEnv(fs, &cfg.Relay.MaxPort, "max-port", 0, utils.ParseOptionalPortNumber, "inclusive maximum lease port shared by UDP and raw TCP transports (0=disabled)", "MAX_PORT")

	utils.StringFlagEnv(fs, &cfg.AdminToken, "admin-token", "", "admin bearer token for relay admin and policy APIs", "ADMIN_TOKEN")
	utils.BoolFlagEnv(fs, &cfg.Relay.PProfEnabled, "pprof-enabled", false, "enable pprof diagnostics HTTP server", "PPROF_ENABLED")
	utils.StringFlagEnv(fs, &cfg.Relay.PProfListenAddr, "pprof-addr", portal.DefaultPProfListenAddr, "pprof diagnostics listen address when enabled", "PPROF_ADDR")
	utils.BoolFlagEnv(fs, &cfg.Relay.X402Enabled, "x402-enabled", false, "enable relay-owned Sui x402 facilitator endpoints under /api/x402 for future control-plane payments", "X402_ENABLED")
	utils.BoolFlagEnv(fs, &cfg.Relay.X402Testnet, "x402-testnet", false, "use Sui testnet for relay-owned x402 facilitator payments", "X402_TESTNET")
	utils.StringFlagEnv(fs, &cfg.Relay.X402PayTo, "x402-pay-to", "", "Sui payment recipient address for relay-owned control-plane x402 resources", "X402_PAY_TO")

	utils.StringFlagEnv(fs, &cfg.Relay.ACME.DNSProvider, "acme-dns-provider", "", "DNS provider for managed DNS-01/A-record sync, ECH HTTPS records, and ENS gasless DNSSEC/TXT automation (embedded|cloudflare|gcloud|hetzner|njalla|route53|vultr); defaults to embedded without API credentials", "ACME_DNS_PROVIDER")
	utils.BoolFlagEnv(fs, &cfg.Relay.ACME.ENSGaslessEnabled, "ens-gasless-enabled", false, "enable ENS gasless DNS import automation for the managed DNS zone and lease hostnames", "ENS_GASLESS_ENABLED")
	utils.IntFlagEnv(fs, &cfg.Relay.ACME.EmbeddedDNSPort, "embedded-dns-port", 53, utils.ParsePortNumber, "listen port for the embedded authoritative DNS server (the default DNS provider); requires a one-time NS delegation of the base domain and open 53/tcp+udp", "EMBEDDED_DNS_PORT")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.CloudflareToken, "cloudflare-token", "", "Cloudflare DNS API token for DNS automation (required when acme-dns-provider=cloudflare)", "CLOUDFLARE_TOKEN")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.GCPProjectID, "gcp-project-id", "", "Google Cloud project id for Cloud DNS automation; auto-detected from ADC or GCE metadata when omitted", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCE_PROJECT")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.GCPManagedZone, "gcp-managed-zone", "", "explicit Google Cloud DNS managed zone name or numeric ID override", "GCP_MANAGED_ZONE", "GCP_ZONE", "GCE_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.HetznerAPIToken, "hetzner-api-token", "", "Hetzner Cloud API token for DNS automation (required when acme-dns-provider=hetzner)", "HETZNER_API_TOKEN", "HCLOUD_TOKEN")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSAccessKeyID, "aws-access-key-id", "", "AWS access key ID for Route53 static credentials; uses the default AWS credential chain when omitted", "AWS_ACCESS_KEY_ID")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key for Route53 static credentials", "AWS_SECRET_ACCESS_KEY")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSSessionToken, "aws-session-token", "", "AWS session token for Route53 temporary credentials", "AWS_SESSION_TOKEN")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSRegion, "aws-region", "", "AWS region for Route53 and Route53-backed DNS-01; defaults to us-east-1 when unset", "AWS_REGION", "AWS_DEFAULT_REGION")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSHostedZoneID, "aws-hosted-zone-id", "", "explicit Route53 hosted zone ID override", "AWS_HOSTED_ZONE_ID")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.AWSKMSKeyARN, "aws-dnssec-kms-key-arn", "", "AWS KMS key ARN used to create a Route53 DNSSEC key-signing key when needed", "AWS_DNSSEC_KMS_KEY_ARN")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.VultrAPIKey, "vultr-api-key", "", "Vultr API key for DNS automation (required when acme-dns-provider=vultr)", "VULTR_API_KEY")
	utils.StringFlagEnv(fs, &cfg.Relay.ACME.NjallaToken, "njalla-token", "", "Njalla API token for DNS automation (required when acme-dns-provider=njalla)", "NJALLA_TOKEN")
}

func runServeCommand(args []string) error {
	cfg, err := resolveAppConfig(args)
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
		Str("state_dir", cfg.Relay.StateDir).
		Int("api_port", cfg.Relay.APIPort).
		Int("sni_port", utils.IntOrDefault(cfg.Relay.SNIPort, portal.DefaultSNIPort(cfg.Relay.PortalURL))).
		Msg("starting relay server")

	ctx, stop := utils.SignalContext()
	defer stop()

	return runServer(ctx, cfg)
}

func runServer(ctx context.Context, cfg appConfig) error {
	server, err := portal.NewServer(cfg.Relay)
	if err != nil {
		return fmt.Errorf("create relay server: %w", err)
	}

	policyPath := filepath.Join(cfg.Relay.StateDir, types.RelayPolicyFilename)
	relayAPI, err := NewRelayAPI(server, policyPath, cfg.AdminToken, cfg.FrontendDir, cfg.LandingPageEnabled)
	if err != nil {
		return fmt.Errorf("create relay api: %w", err)
	}
	if err := relayAPI.applyReputationConfig(cfg.Reputation); err != nil {
		return fmt.Errorf("apply reputation config: %w", err)
	}
	// Stop the reputation reconcile loop when the server exits.
	defer relayAPI.Close()

	return server.Serve(ctx, relayAPI.Handler())
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
	registerAppFlags(fs, &appConfig{})
	utils.WriteFlagDefaults(w, fs)
	utils.WriteHelpSection(w, "Loopback", []string{
		"relay-server --portal-url https://127.0.0.1:8443 --api-port 4017",
		"portal expose 127.0.0.1:8080 --relays https://127.0.0.1:8443 --discovery=false",
	})
	utils.WriteHelpSection(w, "Ready", []string{
		"After portal expose succeeds, it logs a line starting with: service ready at",
	})
}
