package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"expose": runExposeCommand,
		"list":   runListCommand,
		"update": runUpdateCommand,
		"version": func(args []string) error {
			fmt.Fprintln(os.Stdout, types.ReleaseVersion)
			return nil
		},
		"help": utils.MakeHelpCommand(printRootUsage, []utils.HelpTopic{
			{Name: "expose", Usage: printExposeUsage},
			{Name: "list", Usage: printListUsage},
			{Name: "update", Usage: printUpdateUsage},
		}),
	}); err != nil {
		log.Error().Err(err).Msg("portal tunnel exited with error")
		os.Exit(1)
	}
}

type exposeFlags struct {
	relayCSV        string
	multiHopCSV     string
	pepperMode      string
	discovery       bool
	banMITM         bool
	identityPath    string
	identityJSON    string
	name            string
	desc            string
	tags            string
	owner           string
	thumbnail       string
	hide            bool
	targetAddr      string
	httpRoutes      []string
	udp             bool
	udpAddr         string
	tcp             bool
	maxActiveRelays int
	multiHopDepth   int
}

func runExposeCommand(args []string) error {
	installer.StartUpdateCheck(types.ReleaseVersion)

	flags := exposeFlags{}
	fs := utils.NewFlagSet("expose", printExposeUsage)

	utils.StringFlag(fs, &flags.relayCSV, "relays", "", "Additional Portal relay server API URLs (comma-separated; scheme omitted defaults to https)")
	utils.StringFlagEnv(fs, &flags.multiHopCSV, "multi-hop", "", "Ordered multi-hop relay API URLs, comma-separated", "MULTI_HOP")
	utils.StringFlag(fs, &flags.pepperMode, "pepper", "", "Optional pepper mode: active or passive; omitted disables the pepper layer")
	utils.BoolFlag(fs, &flags.discovery, "discovery", true, "Include public registry relays and discover additional relay bootstraps")
	utils.BoolFlagEnv(fs, &flags.banMITM, "ban-mitm", true, "Ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &flags.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &flags.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.StringFlag(fs, &flags.name, "name", "", "Public hostname prefix (single DNS label); auto-generated when omitted")
	utils.StringFlag(fs, &flags.desc, "description", "", "Service description metadata")
	utils.StringFlag(fs, &flags.tags, "tags", "", "Service tags metadata (comma-separated)")
	utils.StringFlag(fs, &flags.owner, "owner", "", "Service owner metadata")
	utils.StringFlag(fs, &flags.thumbnail, "thumbnail", "", "Service thumbnail URL metadata")
	utils.BoolFlag(fs, &flags.hide, "hide", false, "Hide service from relay listing screens")
	utils.RepeatedStringFlag(fs, &flags.httpRoutes, "http-route", "HTTP route mapping in PATH=UPSTREAM form; repeat to aggregate multiple local HTTP services behind one public URL")
	utils.BoolFlagEnv(fs, &flags.udp, "udp", false, "Enable public UDP relay in addition to the default TCP relay", "UDP_ENABLED")
	utils.StringFlagEnv(fs, &flags.udpAddr, "udp-addr", "", "Local UDP target address for relayed datagrams (host:port or port only); defaults to the target when --udp is enabled", "UDP_ADDR")
	utils.BoolFlagEnv(fs, &flags.tcp, "tcp", false, "Request a dedicated TCP port on the relay for raw TCP services (no TLS; e.g., Minecraft, game servers)", "TCP_ENABLED")
	utils.IntFlagEnv(fs, &flags.maxActiveRelays, "max-active-relays", 3, nil, "Maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	utils.IntFlagEnv(fs, &flags.multiHopDepth, "multi-hop-depth", 0, nil, "Automatically select one multi-hop route with this hop count; 0 or 1 disables multi-hop", "MULTI_HOP_DEPTH")

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
	flags.pepperMode = strings.TrimSpace(strings.ToLower(flags.pepperMode))
	if err := sdk.ValidatePepperMode(flags.pepperMode); err != nil {
		printExposeUsage(os.Stderr)
		return err
	}
	switch {
	case flags.targetAddr == "" && len(flags.httpRoutes) == 0:
		printExposeUsage(os.Stderr)
		return errors.New("target or at least one --http-route is required")
	case flags.targetAddr != "" && len(flags.httpRoutes) > 0:
		printExposeUsage(os.Stderr)
		return errors.New("target cannot be combined with --http-route")
	case len(flags.httpRoutes) > 0 && flags.udp:
		printExposeUsage(os.Stderr)
		return errors.New("--udp cannot be combined with --http-route")
	case flags.pepperMode != "" && len(flags.httpRoutes) > 0:
		printExposeUsage(os.Stderr)
		return errors.New("--pepper cannot be combined with --http-route")
	}

	ctx, stop := utils.SignalContext()
	defer stop()

	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:       utils.SplitCSV(flags.relayCSV),
		Discovery:       flags.discovery,
		IdentityPath:    flags.identityPath,
		IdentityJSON:    flags.identityJSON,
		Name:            flags.name,
		TargetAddr:      flags.targetAddr,
		UDPAddr:         flags.udpAddr,
		UDPEnabled:      flags.udp,
		TCPEnabled:      flags.tcp,
		MultiHop:        utils.SplitCSV(flags.multiHopCSV),
		MultiHopDepth:   flags.multiHopDepth,
		PepperMode:      flags.pepperMode,
		BanMITM:         flags.banMITM,
		MaxActiveRelays: flags.maxActiveRelays,
		Metadata: types.LeaseMetadata{
			Description: flags.desc,
			Tags:        utils.SplitCSV(flags.tags),
			Owner:       flags.owner,
			Thumbnail:   flags.thumbnail,
			Hide:        flags.hide,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to start relays: %w", err)
	}
	if len(flags.httpRoutes) > 0 {
		httpRoutes := make([]sdk.HTTPRoute, 0, len(flags.httpRoutes))
		for _, raw := range flags.httpRoutes {
			prefix, upstream, ok := strings.Cut(raw, "=")
			if !ok {
				return fmt.Errorf("--http-route %q: expected PATH=UPSTREAM", raw)
			}
			httpRoutes = append(httpRoutes, sdk.HTTPRoute{
				Prefix:   strings.TrimSpace(prefix),
				Upstream: strings.TrimSpace(upstream),
			})
		}

		defer exposure.Close()
		return exposure.RunHTTPRoutes(ctx, httpRoutes, "")
	}
	return proxyExposure(ctx, exposure)
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
	utils.BoolFlag(fs, &flags.defaultRelays, "default-relays", true, "Include public registry relays")

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

	relayURLs, err := utils.ResolvePortalRelayURLs(ctx, relayInputs, flags.defaultRelays)
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
		if ver == "" {
			ver = "unknown"
		}
		fmt.Fprintf(table, "%s\t%s\n", relayURL, ver)
	}
	return table.Flush()
}

func printRootUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"portal expose [flags] <target>",
			"portal expose [flags] --http-route PATH=UPSTREAM [--http-route PATH=UPSTREAM]",
			"portal list [flags]",
			"portal update [flags]",
			"portal version",
		},
		[]string{
			"portal expose 3000",
			"portal expose localhost:8080 --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
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
			"portal expose [flags] --http-route PATH=UPSTREAM [--http-route PATH=UPSTREAM]",
		},
		[]string{
			"portal expose 3000",
			"portal expose localhost:8080 --name my-app",
			"portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173 --name my-app",
			"portal expose 3000 --udp --udp-addr 127.0.0.1:5353",
			"portal expose 3000 --ban-mitm",
			"portal expose 3000 --relays https://portal.example.com --discovery=false",
			"portal expose 3000 --multi-hop https://entry.example.com,https://transit.example.com,https://exit.example.com",
			"portal expose 3000 --multi-hop-depth 3 --pepper passive",
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
			"portal update --version v2.1.7",
		},
	)
}
