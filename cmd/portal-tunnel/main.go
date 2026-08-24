package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"expose": runExposeCommand,
		"agent":  runAgentCommand,
		"list":   runListCommand,
		"update": runUpdateCommand,
		"version": func(args []string) error {
			fmt.Fprintln(os.Stdout, types.ReleaseVersion)
			return nil
		},
		"help": utils.MakeHelpCommand(printRootUsage, []utils.HelpTopic{
			{Name: "expose", Usage: printExposeUsage},
			{Name: "agent", Usage: printAgentUsage},
			{Name: "list", Usage: printListUsage},
			{Name: "update", Usage: printUpdateUsage},
		}),
	}); err != nil {
		log.Error().Err(err).Msg("portal tunnel exited with error")
		os.Exit(1)
	}
}

type exposeFlags struct {
	relayCSV             string
	multiHopCSV          string
	discovery            bool
	banMITM              bool
	identityPath         string
	identityJSON         string
	name                 string
	desc                 string
	tags                 string
	owner                string
	thumbnail            string
	hide                 bool
	x402PayTo            string
	x402Testnet          bool
	x402Network          string
	x402Asset            string
	x402Endpoints        []string
	x402FacilitatorToken string
	targetAddr           string
	httpRoutes           []string
	serve                string
	udp                  bool
	udpAddr              string
	tcp                  bool
	ech                  bool
	maxActiveRelays      int
	multiHopDepth        int
	metricsAddr          string
}

func runExposeCommand(args []string) error {
	installer.StartUpdateCheck(types.ReleaseVersion)

	flags := exposeFlags{}
	fs := utils.NewFlagSet("expose", printExposeUsage)

	utils.StringFlag(fs, &flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	utils.StringFlagEnv(fs, &flags.multiHopCSV, "multi-hop", "", "Ordered multi-hop relay API URLs, comma-separated", "MULTI_HOP")
	utils.BoolFlag(fs, &flags.discovery, "discovery", true, "Include bootstrap relays and discover additional relays")
	utils.BoolFlagEnv(fs, &flags.banMITM, "ban-mitm", false, "Ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &flags.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &flags.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.StringFlag(fs, &flags.name, "name", "", "Public hostname prefix (single DNS label); auto-generated when omitted")
	utils.StringFlag(fs, &flags.desc, "description", "", "Service description metadata")
	utils.StringFlag(fs, &flags.tags, "tags", "", "Service tags metadata (comma-separated)")
	utils.StringFlag(fs, &flags.owner, "owner", "", "Service owner metadata")
	utils.StringFlag(fs, &flags.thumbnail, "thumbnail", "", "Service thumbnail URL metadata")
	utils.BoolFlag(fs, &flags.hide, "hide", false, "Hide service from relay listing screens")
	utils.StringFlag(fs, &flags.x402PayTo, "x402-pay-to", "", "Payment recipient address for this tunnel")
	utils.BoolFlag(fs, &flags.x402Testnet, "x402-testnet", false, "Use the testnet for x402 payments when --x402-network is omitted; default is Sui mainnet")
	utils.StringFlag(fs, &flags.x402Network, "x402-network", "", "x402 CAIP-2 network; supported values are sui:mainnet, sui:testnet, casper:casper, and casper:casper-test")
	utils.StringFlag(fs, &flags.x402Asset, "x402-asset", "", "Payment asset contract; required for Casper wCSPR")
	utils.RepeatedStringFlag(fs, &flags.x402Endpoints, "x402-endpoint", "x402 chain RPC or hosted facilitator endpoint; repeat for Sui RPC fallback, while Casper uses the first facilitator endpoint")
	utils.StringFlagEnv(fs, &flags.x402FacilitatorToken, "x402-facilitator-token", "", "Casper facilitator authorization token", "CSPR_CLOUD_API_KEY")
	utils.RepeatedStringFlag(fs, &flags.httpRoutes, "http-route", "HTTP route mapping in PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT] form; repeat to aggregate multiple local HTTP services behind one public URL")
	utils.StringFlag(fs, &flags.serve, "serve", "", "Serve a local static site: pass a directory (served with index.html) or an HTML file (its folder is served with that file as the SPA/CSR entry). Unknown paths fall back to the entry file")
	utils.BoolFlagEnv(fs, &flags.udp, "udp", false, "Enable public UDP relay in addition to the default TCP relay", "UDP_ENABLED")
	utils.StringFlagEnv(fs, &flags.udpAddr, "udp-addr", "", "Local UDP target address for relayed datagrams (host:port or port only); defaults to the target when --udp is enabled", "UDP_ADDR")
	utils.BoolFlagEnv(fs, &flags.tcp, "tcp", false, "Request a dedicated TCP port on the relay for raw TCP services (no TLS; e.g., Minecraft, game servers)", "TCP_ENABLED")
	utils.BoolFlagEnv(fs, &flags.ech, "ech", false, "Enable ECH hostname privacy for the default TLS stream transport", "ECH_ENABLED")
	utils.IntFlagEnv(fs, &flags.maxActiveRelays, "max-active-relays", 3, nil, "Maximum auto-selected single-hop relays to keep connected; multi-hop uses every eligible relay as an entry", "MAX_ACTIVE_RELAYS")
	utils.IntFlagEnv(fs, &flags.multiHopDepth, "multi-hop-depth", 0, nil, "Automatically create multi-hop routes at this hop count for every eligible entry relay; 0 or 1 disables multi-hop", "MULTI_HOP_DEPTH")
	utils.StringFlag(fs, &flags.metricsAddr, "metrics-addr", "", "Optional address (host:port) to serve Prometheus /metrics. Empty = disabled.")

	if err := utils.ParseFlagSet(fs, args, printExposeUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var err error
	flags.targetAddr, err = utils.OptionalSingleArg(fs.Args(), "target")
	if err != nil {
		printExposeUsage(os.Stderr)
		return err
	}
	httpRouteInputs := append([]string(nil), flags.httpRoutes...)
	serve := strings.TrimSpace(flags.serve)
	switch {
	case serve != "" && flags.targetAddr != "":
		printExposeUsage(os.Stderr)
		return errors.New("target cannot be combined with --serve")
	case serve != "" && len(httpRouteInputs) > 0:
		printExposeUsage(os.Stderr)
		return errors.New("--serve cannot be combined with --http-route")
	case serve != "" && flags.udp:
		printExposeUsage(os.Stderr)
		return errors.New("--serve cannot be combined with --udp")
	case serve != "" && flags.tcp:
		printExposeUsage(os.Stderr)
		return errors.New("--serve cannot be combined with --tcp")
	case serve == "" && flags.targetAddr == "" && len(httpRouteInputs) == 0:
		printExposeUsage(os.Stderr)
		return errors.New("target, --serve, or at least one --http-route is required")
	case flags.targetAddr != "" && len(flags.httpRoutes) > 0:
		printExposeUsage(os.Stderr)
		return errors.New("target cannot be combined with --http-route")
	case len(httpRouteInputs) > 0 && flags.udp:
		printExposeUsage(os.Stderr)
		return errors.New("--udp cannot be combined with --http-route")
	}

	httpRoutes := make([]sdk.HTTPRouteConfig, 0, len(httpRouteInputs)+1)
	if serve != "" {
		root, index, err := utils.ResolveStaticSite(serve)
		if err != nil {
			printExposeUsage(os.Stderr)
			return fmt.Errorf("--serve %q: %w", serve, err)
		}
		httpRoutes = append(httpRoutes, sdk.HTTPRouteConfig{
			Prefix:      "/",
			StaticRoot:  root,
			StaticIndex: index,
		})
	}
	for _, raw := range httpRouteInputs {
		fields := strings.Fields(raw)
		if len(fields) == 0 || len(fields) > 2 {
			return fmt.Errorf("--http-route %q: expected PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]", raw)
		}
		prefix, upstream, ok := strings.Cut(fields[0], "=")
		if !ok {
			return fmt.Errorf("--http-route %q: expected PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]", raw)
		}
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			return fmt.Errorf("--http-route %q: path is required", raw)
		}
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("--http-route %q: path must start with /", raw)
		}
		upstream = strings.TrimSpace(upstream)
		if upstream == "" {
			return fmt.Errorf("--http-route %q: upstream is required", raw)
		}
		route := sdk.HTTPRouteConfig{
			Prefix:   prefix,
			Upstream: upstream,
		}
		if len(fields) == 2 {
			methods, amount, err := parseHTTPRoutePayment(fields[1])
			if err != nil {
				return fmt.Errorf("--http-route %q: %w", raw, err)
			}
			if strings.TrimSpace(flags.x402PayTo) == "" {
				return fmt.Errorf("--http-route %q: payment amount requires --x402-pay-to", raw)
			}
			route.Methods = methods
			route.Amount = amount
		}
		httpRoutes = append(httpRoutes, route)
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(flags.x402Network)), "casper:") && strings.TrimSpace(flags.x402Asset) == "" {
		return errors.New("--x402-asset is required for Casper wCSPR payments")
	}

	ctx, stop := utils.SignalContext()
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

	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:       utils.SplitCSV(flags.relayCSV),
		Discovery:       flags.discovery,
		Identity:        types.Identity{Name: flags.name},
		IdentityPath:    flags.identityPath,
		IdentityJSON:    flags.identityJSON,
		TargetAddr:      flags.targetAddr,
		UDPAddr:         flags.udpAddr,
		UDPEnabled:      flags.udp,
		TCPEnabled:      flags.tcp,
		ECH:             flags.ech,
		MultiHop:        utils.SplitCSV(flags.multiHopCSV),
		MultiHopDepth:   flags.multiHopDepth,
		BanMITM:         flags.banMITM,
		MaxActiveRelays: flags.maxActiveRelays,
		Metadata: types.LeaseMetadata{
			Description: flags.desc,
			Tags:        utils.SplitCSV(flags.tags),
			Owner:       flags.owner,
			Thumbnail:   flags.thumbnail,
			Hide:        flags.hide,
		},
		X402PayTo:            flags.x402PayTo,
		X402Testnet:          flags.x402Testnet,
		X402Network:          flags.x402Network,
		X402Asset:            flags.x402Asset,
		X402Endpoints:        flags.x402Endpoints,
		X402FacilitatorToken: flags.x402FacilitatorToken,
	})
	if err != nil {
		return fmt.Errorf("failed to start relays: %w", err)
	}
	if len(httpRoutes) > 0 {
		defer exposure.Close()
		return exposure.RunHTTPRoutes(ctx, httpRoutes, "")
	}
	return sdk.ProxyExposure(ctx, exposure)
}

func parseHTTPRoutePayment(value string) ([]string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", errors.New("payment amount is required")
	}
	methodPart, amount, hasMethods := strings.Cut(value, ":")
	if !hasMethods {
		amount = value
		methodPart = ""
	}
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return nil, "", errors.New("payment amount is required")
	}
	methods := []string(nil)
	if hasMethods {
		for rawMethod := range strings.SplitSeq(methodPart, ",") {
			method := strings.ToUpper(strings.TrimSpace(rawMethod))
			if method == "" {
				return nil, "", errors.New("payment method is required")
			}
			exists := slices.Contains(methods, method)
			if !exists {
				methods = append(methods, method)
			}
		}
		if len(methods) == 0 {
			return nil, "", errors.New("payment methods are required before ':'")
		}
	}
	return methods, amount, nil
}

func runUpdateCommand(args []string) error {
	var version string
	fs := utils.NewFlagSet("update", printUpdateUsage)
	utils.StringFlag(fs, &version, "version", "", "Release version to install; defaults to latest")

	if err := utils.ParseFlagSet(fs, args, printUpdateUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "update"); err != nil {
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
	fs := utils.NewFlagSet("list", printListUsage)

	utils.StringFlag(fs, &flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	utils.BoolFlag(fs, &flags.defaultRelays, "default-relays", true, "Include bootstrap relays")

	if err := utils.ParseFlagSet(fs, args, printListUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "list"); err != nil {
		printListUsage(os.Stderr)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayInputs := utils.SplitCSV(flags.relayCSV)

	relayURLs, err := utils.ResolvePortalRelayURLs(relayInputs, flags.defaultRelays)
	if err != nil {
		return fmt.Errorf("resolve relay urls: %w", err)
	}
	if len(relayURLs) == 0 {
		return errors.New("no relay URLs configured")
	}

	versions := make([]string, len(relayURLs))
	var wg sync.WaitGroup
	wg.Add(len(relayURLs))
	for i, u := range relayURLs {
		go func(idx int, url string) {
			defer wg.Done()
			versions[idx] = utils.FetchRelayVersion(ctx, url)
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

func printRootUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --http-route \"PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]\" [...]",
			"portal agent run [flags]",
			"portal agent dashboard [flags]",
			"portal agent stop [flags]",
			"portal agent restart [flags]",
			"portal list [flags]",
			"portal update [flags]",
			"portal version",
		},
		[]string{
			"portal expose 3000",
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
	utils.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --serve <dir|file.html>",
			"portal expose [flags] --http-route \"PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]\" [...]",
		},
		[]string{
			"portal expose 3000",
			"portal expose localhost:8080 --name my-app",
			"portal expose --serve ./site --name my-app",
			"portal expose --serve ./site/main.html --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
			"portal expose --http-route \"/paid=http://127.0.0.1:3001 GET:0.01\" --http-route /=http://127.0.0.1:5173 --x402-pay-to 0x...",
			"portal expose --http-route \"/paid=http://127.0.0.1:3001 GET:0.01\" --x402-network casper:casper-test --x402-asset hash-... --x402-pay-to account-hash-...",
			"portal expose 3000 --udp --udp-addr 127.0.0.1:5353",
			"portal expose 3000 --ban-mitm",
			"portal expose 3000 --relays https://portal.example.com --discovery=false",
			"portal expose 3000 --multi-hop https://entry.example.com,https://transit.example.com,https://exit.example.com",
			"portal expose 3000 --multi-hop-depth 3",
		},
	)
}

func printListUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
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
	utils.WriteCommandUsage(w,
		[]string{
			"portal update [flags]",
		},
		[]string{
			"portal update",
			"portal update --version v2.1.9",
		},
	)
}
