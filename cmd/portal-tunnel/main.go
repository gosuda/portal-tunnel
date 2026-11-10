package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/tunnel"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk/appauth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var (
	errCacheTTLRequiresCache               = errors.New("--cache-ttl requires --cache")
	errStripRequestHeaderRequiresHTTPRoute = errors.New("--strip-request-header requires --http-route, --target, or --auth")
	errAuthSubcommandMustBeIssue           = errors.New("auth subcommand must be issue")
	errTunnelIsRequired                    = errors.New("tunnel is required")
	errSubjectIsRequired                   = errors.New("--subject is required")
	errExpiresMustBePositive               = errors.New("--expires must be positive")
	errNoRelayURLsConfigured               = errors.New("no relay URLs configured")
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := cli.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]cli.CommandFunc{
		"expose": runExposeCommand,
		"agent":  runAgentCommand,
		"auth":   runAuthCommand,
		"list":   runListCommand,
		"update": runUpdateCommand,
		"version": func(args []string) error {
			fmt.Fprintln(os.Stdout, types.ReleaseVersion)
			return nil
		},
		"help": cli.MakeHelpCommand(printRootUsage, []cli.HelpTopic{
			{Name: "expose", Usage: printExposeUsage},
			{Name: "agent", Usage: printAgentUsage},
			{Name: "auth", Usage: printAuthUsage},
			{Name: "list", Usage: printListUsage},
			{Name: "update", Usage: printUpdateUsage},
		}),
	}); err != nil {
		logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		logger.Error().Err(err).Msg("portal tunnel exited with error")
		os.Exit(1)
	}
}

type exposeFlags struct {
	relayCSV    string
	tags        string
	httpRoutes  []string
	discovery   bool
	banMITM     bool
	cache       bool
	cacheTTL    time.Duration
	metricsAddr string
	logFormat   string
}

func registerExposeFlags(fs *flag.FlagSet, cfg *tunnel.Config, flags *exposeFlags) {
	env := cli.NewEnv(os.Environ())
	fs.StringVar(&flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	fs.BoolVar(&flags.discovery, "discovery", true, "Include bootstrap relays and discover additional relays")
	env.Bool(fs, &cfg.Overlay, "overlay", false, "Prefer IVNP overlay transport when available", "OVERLAY_ENABLED")
	env.Bool(fs, &flags.banMITM, "ban-mitm", false, "Ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	env.String(fs, &cfg.IdentityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	env.String(fs, &cfg.IdentityJSON, "identity-json", "", "identity json payload kept in memory; takes precedence over --identity-path", "IDENTITY_JSON")
	fs.StringVar(&cfg.Name, "name", "", "Request a short URL without the Ethereum address (single DNS label, maximum 63 ASCII characters); applies to new identities; omitted for the address-only default service")
	fs.StringVar(&cfg.Description, "description", "", "Service description metadata")
	fs.StringVar(&flags.tags, "tags", "", "Service tags metadata (comma-separated)")
	fs.StringVar(&cfg.Owner, "owner", "", "Service owner metadata")
	fs.StringVar(&cfg.Thumbnail, "thumbnail", "", "Service thumbnail URL metadata")
	fs.BoolVar(&cfg.Hide, "hide", false, "Hide service from relay listing screens")
	fs.StringVar(&cfg.Provider, "auth", "", "Protect HTTP application access with siwe, credential, oidc, saml, or email authentication")
	cli.RepeatedStringFlag(fs, &cfg.Allow, "auth-allow", "Principal allowed to sign in with siwe (Ethereum wallet) or credential (subject); repeat to allow multiple principals (empty allows any valid principal). oidc and saml also read it, as --auth-email-list")
	cli.RepeatedStringFlag(fs, &cfg.EmailList, "auth-email-list", "Who may sign in with oidc, saml, or email: an email address, an @domain, or, for oidc and saml, sub:<subject>; repeat to allow multiple entries (at least one is required)")
	fs.BoolVar(&cfg.IdentityHeaders, "auth-identity-headers", false, "Send authenticated X-Portal-User and X-Portal-Auth headers to HTTP upstreams")
	env.String(fs, &cfg.IdentityProof, "auth-identity-proof", "", "Secret sent as X-Portal-Proof with the identity headers so the upstream can verify they came from Portal (at least 16 visible ASCII characters; requires --auth-identity-headers). Pass it by environment variable, not on the command line, because process lists show arguments", "AUTH_IDENTITY_PROOF")
	env.String(fs, &cfg.OIDCIssuerURL, "auth-oidc-issuer", "", "OIDC issuer URL for --auth oidc", "AUTH_OIDC_ISSUER")
	env.String(fs, &cfg.OIDCClientID, "auth-oidc-client-id", "", "OIDC client ID for --auth oidc", "AUTH_OIDC_CLIENT_ID")
	env.String(fs, &cfg.OIDCClientSecret, "auth-oidc-client-secret", "", "Optional OIDC client secret for --auth oidc", "AUTH_OIDC_CLIENT_SECRET")
	env.String(fs, &cfg.SAMLMetadataURL, "auth-saml-metadata-url", "", "SAML identity provider metadata URL for --auth saml (or use --auth-saml-metadata-file)", "AUTH_SAML_METADATA_URL")
	env.String(fs, &cfg.SAMLMetadataFile, "auth-saml-metadata-file", "", "SAML identity provider metadata file for --auth saml, for an identity provider that publishes no metadata URL", "AUTH_SAML_METADATA_FILE")
	env.String(fs, &cfg.SAMLEntityID, "auth-saml-entity-id", "", "SAML service provider entity ID for --auth saml (default https://<host>/_portal/auth/saml/metadata)", "AUTH_SAML_ENTITY_ID")
	env.String(fs, &cfg.SAMLSubjectAttribute, "auth-saml-subject-attribute", "", "SAML attribute that names the visitor for --auth saml, such as email (default: the NameID)", "AUTH_SAML_SUBJECT_ATTRIBUTE")
	env.String(fs, &cfg.SMTPAddr, "auth-smtp-addr", "", "SMTP server host:port that sends the login links of --auth email (port 465 uses TLS; any other port requires STARTTLS, except on localhost, 127.0.0.1, or ::1)", "AUTH_SMTP_ADDR")
	env.String(fs, &cfg.SMTPUsername, "auth-smtp-username", "", "Optional SMTP username for --auth email; requires --auth-smtp-password", "AUTH_SMTP_USERNAME")
	env.String(fs, &cfg.SMTPPassword, "auth-smtp-password", "", "SMTP password for --auth email. Pass it by environment variable, not on the command line, because process lists show arguments", "AUTH_SMTP_PASSWORD")
	env.String(fs, &cfg.SMTPFrom, "auth-smtp-from", "", "Fixed sender address of the login links of --auth email, such as \"Portal <login@example.com>\"", "AUTH_SMTP_FROM")
	fs.StringVar(&cfg.PayTo, "x402-pay-to", "", "Payment recipient address for this tunnel")
	fs.BoolVar(&cfg.Testnet, "x402-testnet", false, "Use the testnet for x402 payments when --x402-network is omitted; default is Sui mainnet")
	fs.StringVar(&cfg.Network, "x402-network", "", "x402 CAIP-2 network; supported values are sui:mainnet, sui:testnet, casper:casper, casper:casper-test, and nano:mainnet")
	fs.StringVar(&cfg.Asset, "x402-asset", "", "Payment asset contract; required for Casper wCSPR")
	cli.RepeatedStringFlag(fs, &cfg.Endpoints, "x402-endpoint", "x402 chain RPC or hosted facilitator endpoint; repeat for Sui RPC fallback, while Casper uses the first facilitator endpoint and Nano verifies each payment on every listed RPC node (at least two)")
	env.String(fs, &cfg.FacilitatorToken, "x402-facilitator-token", "", "Casper facilitator authorization token", "CSPR_CLOUD_API_KEY")
	cli.RepeatedStringFlag(fs, &flags.httpRoutes, "http-route", "HTTP route mapping in PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT] form; repeat to aggregate multiple local HTTP services behind one public URL")
	cli.RepeatedStringFlag(fs, &cfg.StripRequestHeaders, "strip-request-header", "Client request header removed before routed HTTP forwards it upstream; repeat for multiple headers; case-insensitive; applies to HTTP and WebSocket upgrades; Portal-owned headers (Host, X-Forwarded-*) are always rewritten by the tunnel; requires --http-route or --auth")
	fs.StringVar(&cfg.Serve, "serve", "", "Serve a local static site: pass a directory (served with index.html) or an HTML file (its folder is served with that file as the SPA/CSR entry). Unknown paths fall back to the entry file")
	fs.BoolVar(&flags.cache, "cache", false, "Allow selected relays to store --serve content and terminate browser TLS; cached responses lose end-to-end TLS to this client")
	fs.DurationVar(&flags.cacheTTL, "cache-ttl", 0, "Requested offline cache lifetime, clamped by the relay; 0 uses relay policy (requires --cache)")
	env.Bool(fs, &cfg.UDPEnabled, "udp", false, "Enable public UDP relay in addition to the default TCP relay", "UDP_ENABLED")
	env.String(fs, &cfg.UDPAddr, "udp-addr", "", "Local UDP target address for relayed datagrams (host:port or port only); defaults to the target when --udp is enabled", "UDP_ADDR")
	env.Bool(fs, &cfg.TCPEnabled, "tcp", false, "Request a dedicated TCP port on the relay for raw TCP services (no TLS; e.g., Minecraft, game servers)", "TCP_ENABLED")
	env.Int(fs, &cfg.MaxActiveRelays, "max-active-relays", discovery.DefaultMaxActiveRelays, nil, "Maximum auto-selected public relays to keep connected", "MAX_ACTIVE_RELAYS")
	fs.StringVar(&flags.metricsAddr, "metrics-addr", "", "Optional address (host:port) to serve Prometheus /metrics. Empty = disabled.")
	fs.StringVar(&flags.logFormat, "log-format", "text", "Log output format: text (default human-readable console) or json (one structured JSON log record per line on stdout; integrations filter relay lifecycle records by event=relay_status)")
}

func runExposeCommand(args []string) error {
	installer.StartUpdateCheck(types.ReleaseVersion)

	var cfg tunnel.Config
	var flags exposeFlags
	fs := cli.NewFlagSet("expose", printExposeUsage)
	registerExposeFlags(fs, &cfg, &flags)
	if err := cli.ParseFlagSet(fs, args, printExposeUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	switch flags.logFormat {
	case "", "text", "json":
	default:
		return fmt.Errorf("--log-format %q: supported values are text and json", flags.logFormat)
	}
	if flags.logFormat == "json" {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
	var err error
	cfg.TargetAddr, err = cli.OptionalSingleArg(fs.Args(), "target")
	if err != nil {
		printExposeUsage(os.Stderr)
		return err
	}
	spec, err := tunnelSpecFromExposeFlags(fs, cfg, flags)
	if err != nil {
		printExposeUsage(os.Stderr)
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	if flags.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{
			Addr:              flags.metricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info().Str("metrics_addr", flags.metricsAddr).Msg("metrics server listening")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("metrics server error")
			}
		}()
	}

	runtime, err := tunnel.Start(ctx, spec)
	if err != nil {
		return err
	}
	defer runtime.Close()
	return runtime.Run(ctx)
}

func tunnelSpecFromExposeFlags(fs *flag.FlagSet, cfg tunnel.Config, flags exposeFlags) (tunnel.Spec, error) {
	if !flags.cache && flags.cacheTTL != 0 {
		return tunnel.Spec{}, errCacheTTLRequiresCache
	}
	for _, raw := range flags.httpRoutes {
		route, err := tunnel.ParseHTTPRoute(raw)
		if err != nil {
			return tunnel.Spec{}, fmt.Errorf("--http-route %q: %w", raw, err)
		}
		cfg.HTTPRoutes = append(cfg.HTTPRoutes, route)
	}
	cfg.RelayURLs = utils.SplitCSV(flags.relayCSV)
	cfg.Tags = utils.SplitCSV(flags.tags)
	cfg.Discovery = &flags.discovery
	cfg.BanMITM = &flags.banMITM
	if flags.cache {
		cfg.Cache = &tunnel.CacheConfig{TTL: flags.cacheTTL}
	}
	oidcFlagGiven, samlFlagGiven, emailFlagGiven, proofFlagGiven := false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		oidcFlagGiven = oidcFlagGiven || strings.HasPrefix(f.Name, "auth-oidc-")
		samlFlagGiven = samlFlagGiven || strings.HasPrefix(f.Name, "auth-saml-")
		emailFlagGiven = emailFlagGiven || strings.HasPrefix(f.Name, "auth-smtp-")
		proofFlagGiven = proofFlagGiven || f.Name == "auth-identity-proof"
	})
	normalized, _ := cfg.AuthConfig.Normalize()
	provider := normalized.Provider
	if provider != appauth.ProviderOIDC && !oidcFlagGiven {
		cfg.OIDCConfig = appauth.OIDCConfig{}
	}
	if provider != appauth.ProviderSAML && !samlFlagGiven {
		cfg.SAMLConfig = appauth.SAMLConfig{}
	}
	if provider != appauth.ProviderEmail && !emailFlagGiven {
		cfg.EmailConfig = appauth.EmailConfig{}
	}
	if !cfg.IdentityHeaders && !proofFlagGiven {
		cfg.IdentityProof = ""
	}
	auth := cfg.AuthConfig
	hasHTTPSource := strings.TrimSpace(cfg.Serve) != "" || len(cfg.HTTPRoutes) > 0 || strings.TrimSpace(cfg.TargetAddr) != ""
	if len(cfg.StripRequestHeaders) > 0 && !hasHTTPSource && auth.IsZero() && cfg.Cache == nil {
		return tunnel.Spec{}, errStripRequestHeaderRequiresHTTPRoute
	}
	return cfg.Spec()
}

func runAuthCommand(args []string) error {
	env := cli.NewEnv(os.Environ())
	if len(args) == 0 || args[0] != "issue" {
		printAuthUsage(os.Stderr)
		return errAuthSubcommandMustBeIssue
	}
	var subject, identityPath, identityJSON string
	var expires time.Duration
	fs := cli.NewFlagSet("auth issue", printAuthUsage)
	fs.StringVar(&subject, "subject", "", "Subject granted access")
	fs.DurationVar(&expires, "expires", 30*24*time.Hour, "Credential lifetime")
	env.String(fs, &identityPath, "identity-path", "identity.json", "Existing tunnel identity json file path", "IDENTITY_PATH")
	env.String(fs, &identityJSON, "identity-json", "", "Existing tunnel identity json payload", "IDENTITY_JSON")
	if err := cli.ParseFlagSet(fs, args[1:], printAuthUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	host, err := cli.OptionalSingleArg(fs.Args(), "tunnel")
	if err != nil || host == "" {
		printAuthUsage(os.Stderr)
		if err != nil {
			return err
		}
		return errTunnelIsRequired
	}
	if strings.TrimSpace(subject) == "" {
		return errSubjectIsRequired
	}
	if expires <= 0 {
		return errExpiresMustBePositive
	}
	tunnelIdentity, err := identity.LoadExisting(identityPath, identityJSON)
	if err != nil {
		return fmt.Errorf("load tunnel identity: %w", err)
	}
	credential, err := appauth.IssueCredential(tunnelIdentity, host, subject, time.Now().UTC().Add(expires))
	if err != nil {
		return err
	}
	redeemURL, err := appauth.CredentialRedeemURL(host, credential)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Credential: %s\nRedeem URL: %s\n", credential, redeemURL)
	return nil
}

func runUpdateCommand(args []string) error {
	var version string
	fs := cli.NewFlagSet("update", printUpdateUsage)
	fs.StringVar(&version, "version", "", "Release version to install; defaults to latest")

	if err := cli.ParseFlagSet(fs, args, printUpdateUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "update"); err != nil {
		printUpdateUsage(os.Stderr)
		return err
	}

	if err := installer.UpdateCurrentBinary(version); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Updated portal.")
	return nil
}

type listFlags struct {
	relayCSV      string
	defaultRelays bool
}

func runListCommand(args []string) error {
	installer.StartUpdateCheck(types.ReleaseVersion)

	flags := listFlags{}
	fs := cli.NewFlagSet("list", printListUsage)

	fs.StringVar(&flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	fs.BoolVar(&flags.defaultRelays, "default-relays", true, "Include bootstrap relays")

	if err := cli.ParseFlagSet(fs, args, printListUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "list"); err != nil {
		printListUsage(os.Stderr)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayInputs := utils.SplitCSV(flags.relayCSV)

	relayURLs, err := discovery.ResolveRelayURLs(relayInputs, flags.defaultRelays)
	if err != nil {
		return fmt.Errorf("resolve relay urls: %w", err)
	}
	if len(relayURLs) == 0 {
		return errNoRelayURLsConfigured
	}

	versions := make([]string, len(relayURLs))
	var wg sync.WaitGroup
	wg.Add(len(relayURLs))
	for i, u := range relayURLs {
		go func(idx int, url string) {
			defer wg.Done()
			versions[idx] = fetchRelayVersion(ctx, url)
		}(i, u)
	}
	wg.Wait()

	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "RELAY\tVERSION")
	for i, relayURL := range relayURLs {
		ver := versions[i]
		ver = cmp.Or(ver, "unknown")
		fmt.Fprintf(table, "%s\t%s\n", relayURL, ver)
	}
	return table.Flush()
}

func fetchRelayVersion(ctx context.Context, relayURL string) string {
	client := utils.NewHTTPClient(utils.WithHTTPTimeout(3 * time.Second))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relayURL+types.PathSDKDomain, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var envelope types.APIEnvelope[types.DomainResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil || !envelope.OK {
		return ""
	}
	return envelope.Data.ReleaseVersion
}

func printRootUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --http-route \"PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]\" [...]",
			"portal agent run [flags]",
			"portal auth issue [flags] <host>",
			"portal agent dashboard [flags]",
			"portal agent stop [flags]",
			"portal agent restart [flags]",
			"portal list [flags]",
			"portal update [flags]",
			"portal version",
		},
		[]string{
			"portal expose 3000",
			"portal expose 3000 --auth siwe",
			"portal expose 3000 --auth credential",
			"portal expose 3000 --auth oidc --auth-oidc-issuer https://accounts.google.com --auth-oidc-client-id <id> --auth-email-list alice@example.com",
			"portal expose 3000 --auth saml --auth-saml-metadata-url https://idp.example/realms/main/protocol/saml/descriptor --auth-email-list @example.com",
			"portal expose 3000 --auth email --auth-smtp-addr smtp.gmail.com:587 --auth-smtp-username me@gmail.com --auth-smtp-from me@gmail.com --auth-email-list alice@example.com   # with AUTH_SMTP_PASSWORD in the environment",
			"portal auth issue gentle-puffin-jam.gosunuts.xyz --subject alice --expires 720h",
			"portal expose localhost:8080 --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
			"portal expose --http-route \"/paid=http://127.0.0.1:3001 GET:0.01\" --http-route /=http://127.0.0.1:5173 --x402-pay-to 0x...",
			"portal expose --http-route \"/paid=http://127.0.0.1:3001 GET:0.01\" --x402-network casper:casper-test --x402-asset hash-... --x402-pay-to account-hash-...",
			"portal agent run",
			"portal agent dashboard",
			"portal agent stop",
			"portal agent restart",
			"portal expose 3000 --udp --udp-addr 127.0.0.1:5353",
			"portal list",
			"portal update",
			"portal update --version v2.1.7",
			"portal version",
		},
	)
}

func printExposeUsage(w io.Writer) {
	if w == nil {
		return
	}
	cli.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --serve <dir|file.html>",
			"portal expose [flags] --http-route \"PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]\" [...]",
		},
		[]string{
			"portal expose 3000",
			"portal expose 3000 --auth siwe",
			"portal expose localhost:8080 --name my-app",
			"portal expose --serve ./dist",
			"portal expose --http-route /api=3001 --http-route /=5173",
			"portal expose localhost:25565 --tcp",
			"portal expose 3000 --overlay",
		},
	)
	fs := cli.NewFlagSet("expose", nil)
	registerExposeFlags(fs, &tunnel.Config{}, &exposeFlags{})
	common := flag.NewFlagSet("Common flags", flag.ContinueOnError)
	advanced := flag.NewFlagSet("Advanced flags", flag.ContinueOnError)
	fs.VisitAll(func(f *flag.Flag) {
		group := advanced
		switch f.Name {
		case "name", "relays", "discovery", "overlay", "http-route", "serve", "tcp", "udp",
			"auth", "auth-allow", "auth-email-list", "x402-pay-to", "ban-mitm", "identity-path":
			group = common
		}
		group.Var(f.Value, f.Name, f.Usage)
		group.Lookup(f.Name).DefValue = f.DefValue
	})
	for _, group := range []*flag.FlagSet{common, advanced} {
		fmt.Fprintf(w, "\n%s:\n", group.Name())
		group.SetOutput(w)
		group.PrintDefaults()
	}
	cli.WriteHelpSection(w, "Loopback", []string{
		"portal expose 127.0.0.1:8080 --identity-path /absolute/path/outside/repo/identity.json --relays https://127.0.0.1:8443 --discovery=false",
		"the local relay must advertise the same origin clients dial: PORTAL_URL=https://127.0.0.1:8443",
	})
	cli.WriteHelpSection(w, "Ready", []string{
		"On success the process logs a line starting with: service ready at",
		"Integrations: --log-format json emits structured relay_status log records on stdout",
	})
}

func printAuthUsage(w io.Writer) {
	env := cli.NewEnv(nil)
	cli.WriteCommandUsage(w, []string{"portal auth issue [flags] <host>"}, []string{"portal auth issue gentle-puffin-jam.gosunuts.xyz --subject alice --expires 720h"})
	fs := cli.NewFlagSet("auth issue", nil)
	var subject, identityPath, identityJSON string
	var expires time.Duration
	fs.StringVar(&subject, "subject", "", "Subject granted access")
	fs.DurationVar(&expires, "expires", 30*24*time.Hour, "Credential lifetime")
	env.String(fs, &identityPath, "identity-path", "identity.json", "Existing tunnel identity json file path", "IDENTITY_PATH")
	env.String(fs, &identityJSON, "identity-json", "", "Existing tunnel identity json payload", "IDENTITY_JSON")
	cli.WriteFlagDefaults(w, fs)
}

func printListUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{
			"portal list [flags]",
		},
		[]string{
			"portal list",
			"portal list --relays https://portal.example.com --default-relays=false",
		},
	)
}

func printUpdateUsage(w io.Writer) {
	cli.WriteCommandUsage(w,
		[]string{
			"portal update [flags]",
		},
		[]string{
			"portal update",
			"portal update --version v2.1.9",
		},
	)
}
