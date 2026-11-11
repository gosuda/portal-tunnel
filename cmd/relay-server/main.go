package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/relay-server/policy"
	"github.com/gosuda/portal-tunnel/v2/portal"
	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	errOnlyOneHelpTopicSupported = errors.New("only one help topic is supported")
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
	X402Enabled       bool
	X402Testnet       bool
	X402PayTo         string
}

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

	env.Bool(fs, &cfg.Relay.TenantCertificates, "tenant-certificates", false, "allow explicitly approved tenants to request certificates using shared CA quota", "TENANT_CERTIFICATES")
	env.String(fs, &cfg.Relay.ACME.TenantIssuanceStateDir, "tenant-issuance-state-dir", "", "durable lock-coherent directory shared by every relay using the same CA quota; required for public tenant issuance", "TENANT_ISSUANCE_STATE_DIR")
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
