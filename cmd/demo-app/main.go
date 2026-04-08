package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := utils.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]utils.CommandFunc{
		"":    runTCPCommand,
		"tcp": runTCPCommand,
		"udp": runUDPCommand,
		"help": utils.MakeHelpCommand(printRootUsage, []utils.HelpTopic{
			{Name: "tcp", Usage: printTCPUsage},
			{Name: "udp", Usage: printUDPUsage},
		}),
	}); err != nil {
		log.Error().Err(err).Msg("demo command failed")
		os.Exit(1)
	}
}

type demoConfig struct {
	relayURLs    string
	discovery    bool
	banMITM      bool
	identityPath string
	identityJSON string
	addr         string
	name         string
	desc         string
	tags         string
	owner        string
	hide         bool
	thumbnail    string
}

// registerConnectivityFlags registers the relay, discovery, identity, and
// owner flags that are shared across TCP and UDP demo commands.
func registerConnectivityFlags(fs *flag.FlagSet, cfg *demoConfig, defaultRelays string) {
	utils.StringFlagEnv(fs, &cfg.relayURLs, "relays", defaultRelays, "additional relay API URLs (comma-separated; scheme omitted defaults to https; merged with public registry relays when discovery is enabled)", "RELAYS")
	utils.BoolFlagEnv(fs, &cfg.discovery, "discovery", true, "include public registry relays and enable discovery", "DISCOVERY")
	utils.BoolFlagEnv(fs, &cfg.banMITM, "ban-mitm", false, "ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	utils.StringFlagEnv(fs, &cfg.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	utils.StringFlagEnv(fs, &cfg.identityJSON, "identity-json", "", "identity json payload; overrides --identity-path contents and is persisted there when both are set", "IDENTITY_JSON")
	utils.StringFlag(fs, &cfg.owner, "owner", "PortalApp Developer", "lease owner")
}

func runTCPCommand(args []string) error {
	cfg := demoConfig{}

	fs := utils.NewFlagSet("demo-app", printTCPUsage)
	registerConnectivityFlags(fs, &cfg, "https://gosunuts.xyz")
	utils.StringFlag(fs, &cfg.addr, "addr", "127.0.0.1:8092", "local demo HTTP listen address (host:port or URL; disable if empty)")
	utils.StringFlag(fs, &cfg.name, "name", "demo-app", "public hostname prefix (single DNS label)")
	utils.StringFlag(fs, &cfg.desc, "description", "Portal demo connectivity app", "lease description")
	utils.StringFlag(fs, &cfg.tags, "tags", "demo,connectivity,activity,cloud,sun,morning", "comma-separated lease tags")
	utils.StringFlag(fs, &cfg.thumbnail, "thumbnail", "https://picsum.photos/640/360", "lease thumbnail")
	utils.BoolFlag(fs, &cfg.hide, "hide", false, "hide this lease from listings")

	if err := utils.ParseFlagSet(fs, args, printTCPUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "demo-app"); err != nil {
		printTCPUsage(os.Stderr)
		return err
	}
	normalizedName, err := utils.NormalizeDNSLabel(cfg.name)
	if err != nil {
		return fmt.Errorf("invalid --name value: %w", err)
	}
	cfg.name = normalizedName

	ctx, stop := utils.SignalContext()
	defer stop()

	return runTCPDemo(ctx, cfg)
}

func runUDPCommand(args []string) error {
	cfg := demoConfig{}
	fs := utils.NewFlagSet("demo-app-udp", printUDPUsage)

	registerConnectivityFlags(fs, &cfg, "https://localhost:4017")
	utils.StringFlag(fs, &cfg.name, "name", "demo-udp", "public hostname prefix (single DNS label)")
	utils.StringFlag(fs, &cfg.desc, "description", "Portal demo UDP echo service", "lease description")
	utils.StringFlag(fs, &cfg.tags, "tags", "demo,udp,echo", "comma-separated lease tags")
	utils.StringFlag(fs, &cfg.thumbnail, "thumbnail", "", "lease thumbnail")
	utils.BoolFlag(fs, &cfg.hide, "hide", true, "hide this lease from listings")

	if err := utils.ParseFlagSet(fs, args, printUDPUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := utils.RequireNoArgs(fs.Args(), "udp"); err != nil {
		printUDPUsage(os.Stderr)
		return err
	}
	normalizedName, err := utils.NormalizeDNSLabel(cfg.name)
	if err != nil {
		return fmt.Errorf("invalid --name value: %w", err)
	}
	cfg.name = normalizedName

	ctx, stop := utils.SignalContext()
	defer stop()

	return runUDPDemo(ctx, cfg)
}

func runTCPDemo(ctx context.Context, cfg demoConfig) error {
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:    utils.SplitCSV(cfg.relayURLs),
		IdentityPath: cfg.identityPath,
		IdentityJSON: cfg.identityJSON,
		Name:         cfg.name,
		BanMITM:      cfg.banMITM,
		Discovery:    cfg.discovery,
		MaxRouting:   types.MinDiscoveryRoutingAttempts,
		Metadata: types.LeaseMetadata{
			Description: cfg.desc,
			Tags:        utils.SplitCSV(cfg.tags),
			Owner:       cfg.owner,
			Thumbnail:   cfg.thumbnail,
			Hide:        cfg.hide,
		},
	})
	if err != nil {
		return fmt.Errorf("exposure listen error: %w", err)
	}

	rawAddr := cfg.addr
	cfg.addr, err = utils.NormalizeTargetAddr(cfg.addr)
	if err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", rawAddr, err)
	}
	httpHandler := newHandler()
	defer exposure.Close()
	err = exposure.RunHTTP(ctx, httpHandler, cfg.addr)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		return err
	}

	if ctx.Err() != nil {
		log.Info().Msg("demo app shutting down")
	}
	log.Info().Msg("demo app shutdown complete")
	return nil
}

func runUDPDemo(ctx context.Context, cfg demoConfig) error {
	exposure, err := sdk.Expose(ctx, sdk.ExposeConfig{
		RelayURLs:    utils.SplitCSV(cfg.relayURLs),
		IdentityPath: cfg.identityPath,
		IdentityJSON: cfg.identityJSON,
		Name:         cfg.name,
		UDPEnabled:   true,
		BanMITM:      cfg.banMITM,
		Discovery:    cfg.discovery,
		MaxRouting:   types.MinDiscoveryRoutingAttempts,
		Metadata: types.LeaseMetadata{
			Description: cfg.desc,
			Tags:        utils.SplitCSV(cfg.tags),
			Owner:       cfg.owner,
			Thumbnail:   cfg.thumbnail,
			Hide:        cfg.hide,
		},
	})
	if err != nil {
		return fmt.Errorf("exposure listen error: %w", err)
	}
	defer exposure.Close()

	udpAddrs, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		return fmt.Errorf("wait for udp readiness: %w", err)
	}
	for _, udpAddr := range udpAddrs {
		log.Info().Str("udp_addr", udpAddr).Msg("demo udp relay ready")
	}

	go runUDPEchoLoop(ctx, exposure)

	if err := exposure.RunHTTP(ctx, newUDPInfoHandler(exposure), ""); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil
		}
		return err
	}

	if ctx.Err() != nil {
		log.Info().Msg("demo udp shutting down")
	}
	log.Info().Msg("demo udp shutdown complete")
	return nil
}

func runUDPEchoLoop(ctx context.Context, exposure *sdk.Exposure) {
	for {
		frame, err := exposure.AcceptDatagram()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn().Err(err).Msg("demo udp accept failed")
			return
		}

		payload := append([]byte(nil), frame.Payload...)
		if len(payload) == 0 {
			payload = []byte("pong")
		}
		frame.Payload = payload
		if err := exposure.SendDatagram(frame); err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Uint32("flow_id", frame.FlowID).Msg("demo udp reply failed")
			return
		}
	}
}

func printRootUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"demo-app [flags]",
			"demo-app tcp [flags]",
			"demo-app udp [flags]",
			"demo-app help",
		},
		[]string{
			"demo-app",
			"demo-app --name my-app",
			"demo-app tcp --addr 127.0.0.1:9000",
			"demo-app udp",
		},
	)
}

func printTCPUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"demo-app [flags]",
			"demo-app tcp [flags]",
		},
		[]string{
			"demo-app",
			"demo-app --name my-app",
			"demo-app tcp --addr 127.0.0.1:9000",
		},
	)
}

func printUDPUsage(w io.Writer) {
	utils.WriteCommandUsage(w,
		[]string{
			"demo-app udp [flags]",
		},
		[]string{
			"demo-app udp",
			"demo-app udp --name my-udp-demo",
			"demo-app udp --discovery=true",
		},
	)
}
