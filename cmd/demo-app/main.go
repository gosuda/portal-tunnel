package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/cmd/internal/cli"
	"github.com/gosuda/portal-tunnel/v2/portal/identity"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())
	if err := cli.RunCommands(os.Args[1:], os.Stdout, os.Stderr, printRootUsage, map[string]cli.CommandFunc{
		"":    runTCPCommand,
		"tcp": runTCPCommand,
		"udp": runUDPCommand,
		"help": cli.MakeHelpCommand(printRootUsage, []cli.HelpTopic{
			{Name: "tcp", Usage: printTCPUsage},
			{Name: "udp", Usage: printUDPUsage},
		}),
	}); err != nil {
		log.Error().Err(err).Msg("demo command failed")
		os.Exit(1)
	}
}

type demoConfig struct {
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
	maxActiveRelays int
}

// registerConnectivityFlags registers the relay, discovery, identity, and
// owner flags that are shared across TCP and UDP demo commands.
func registerConnectivityFlags(fs *flag.FlagSet, cfg *demoConfig, defaultRelays string) {
	env := cli.NewEnv(os.Environ())
	env.String(fs, &cfg.relayURLs, "relays", defaultRelays, "additional relay API URLs (comma-separated; scheme omitted defaults to https; merged with bootstrap relays when discovery is enabled)", "RELAYS")
	env.Bool(fs, &cfg.discovery, "discovery", true, "include bootstrap relays and enable discovery", "DISCOVERY")
	env.Bool(fs, &cfg.banMITM, "ban-mitm", false, "ban relay when the MITM self-probe detects TLS termination", "BAN_MITM")
	env.String(fs, &cfg.identityPath, "identity-path", "identity.json", "identity json file path", "IDENTITY_PATH")
	env.String(fs, &cfg.identityJSON, "identity-json", "", "identity json payload kept in memory; takes precedence over --identity-path", "IDENTITY_JSON")
	env.Int(fs, &cfg.maxActiveRelays, "max-active-relays", 3, nil, "maximum number of auto-selected relays to keep connected; explicit --relays are always included", "MAX_ACTIVE_RELAYS")
	fs.StringVar(&cfg.owner, "owner", "PortalApp Developer", "lease owner")
}

func runTCPCommand(args []string) error {
	cfg := demoConfig{}

	fs := cli.NewFlagSet("demo-app", printTCPUsage)
	registerConnectivityFlags(fs, &cfg, "https://gosunuts.xyz")
	fs.StringVar(&cfg.addr, "addr", "127.0.0.1:8092", "local demo HTTP listen address (host:port or URL; disable if empty)")
	fs.StringVar(&cfg.name, "name", "demo-app", "public hostname prefix (normalized single DNS label, maximum 63 ASCII characters)")
	fs.StringVar(&cfg.desc, "description", "Portal demo connectivity app", "lease description")
	fs.StringVar(&cfg.tags, "tags", "demo,connectivity,activity,cloud,sun,morning", "comma-separated lease tags")
	fs.StringVar(&cfg.thumbnail, "thumbnail", "https://picsum.photos/640/360", "lease thumbnail")
	fs.BoolVar(&cfg.hide, "hide", false, "hide this lease from listings")

	if err := cli.ParseFlagSet(fs, args, printTCPUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "demo-app"); err != nil {
		printTCPUsage(os.Stderr)
		return err
	}
	normalizedName, err := utils.NormalizeDNSLabel(cfg.name)
	if err != nil {
		return fmt.Errorf("invalid --name value: %w", err)
	}
	cfg.name = normalizedName

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	return runTCPDemo(ctx, cfg)
}

func runUDPCommand(args []string) error {
	cfg := demoConfig{}
	fs := cli.NewFlagSet("demo-app-udp", printUDPUsage)

	registerConnectivityFlags(fs, &cfg, "https://localhost")
	fs.StringVar(&cfg.name, "name", "demo-udp", "public hostname prefix (normalized single DNS label, maximum 63 ASCII characters)")
	fs.StringVar(&cfg.desc, "description", "Portal demo UDP echo service", "lease description")
	fs.StringVar(&cfg.tags, "tags", "demo,udp,echo", "comma-separated lease tags")
	fs.StringVar(&cfg.thumbnail, "thumbnail", "", "lease thumbnail")
	fs.BoolVar(&cfg.hide, "hide", true, "hide this lease from listings")

	if err := cli.ParseFlagSet(fs, args, printUDPUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := cli.RequireNoArgs(fs.Args(), "udp"); err != nil {
		printUDPUsage(os.Stderr)
		return err
	}
	normalizedName, err := utils.NormalizeDNSLabel(cfg.name)
	if err != nil {
		return fmt.Errorf("invalid --name value: %w", err)
	}
	cfg.name = normalizedName

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	return runUDPDemo(ctx, cfg)
}

func runTCPDemo(ctx context.Context, cfg demoConfig) error {
	metadata := types.LeaseMetadata{
		Description: cfg.desc,
		Tags:        utils.SplitCSV(cfg.tags),
		Owner:       cfg.owner,
		Thumbnail:   cfg.thumbnail,
		Hide:        cfg.hide,
	}
	listenerIdentity, err := resolveDemoIdentity(cfg)
	if err != nil {
		return err
	}
	exposure, err := exposeDemo(ctx, cfg, listenerIdentity, sdk.WithMetadata(metadata))
	if err != nil {
		return fmt.Errorf("exposure listen error: %w", err)
	}

	rawAddr := cfg.addr
	cfg.addr, err = utils.NormalizeTargetAddr(cfg.addr)
	if err != nil {
		return fmt.Errorf("invalid --addr value %q: %w", rawAddr, err)
	}
	defer exposure.Close()
	err = sdk.RunHTTP(ctx, exposure, newHandler(), cfg.addr)
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
	listenerIdentity, err := resolveDemoIdentity(cfg)
	if err != nil {
		return err
	}
	exposure, err := exposeDemo(ctx, cfg, listenerIdentity,
		sdk.WithUDP(),
		sdk.WithMetadata(types.LeaseMetadata{
			Description: cfg.desc,
			Tags:        utils.SplitCSV(cfg.tags),
			Owner:       cfg.owner,
			Thumbnail:   cfg.thumbnail,
			Hide:        cfg.hide,
		}),
	)
	if err != nil {
		return fmt.Errorf("exposure listen error: %w", err)
	}
	defer exposure.Close()

	udpRelays, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		return fmt.Errorf("wait for udp readiness: %w", err)
	}
	for _, relay := range udpRelays {
		log.Info().Str("udp_addr", relay.UDPAddr).Str("relay_url", relay.RelayURL).Msg("demo udp relay ready")
	}

	go runUDPEchoLoop(ctx, exposure)

	if err := sdk.RunHTTP(ctx, exposure, newUDPInfoHandler(exposure), ""); err != nil {
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

func exposeDemo(ctx context.Context, cfg demoConfig, identity types.Identity, opts ...sdk.Option) (*sdk.Exposure, error) {
	explicitRelayURLs, err := utils.NormalizeRelayURLs(utils.SplitCSV(cfg.relayURLs)...)
	if err != nil {
		return nil, err
	}
	opts = append(opts, sdk.WithMITMProtection(cfg.banMITM))
	if cfg.discovery {
		opts = append(opts, sdk.WithDiscovery(cfg.maxActiveRelays))
	}
	return sdk.Expose(ctx, identity, explicitRelayURLs, opts...)
}

// resolveDemoIdentity parses an inline identity or existing file. It generates
// and persists an identity only when neither source exists.
func resolveDemoIdentity(cfg demoConfig) (types.Identity, error) {
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
	generated, err := identity.Generate(strings.TrimSpace(cfg.name))
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

		payload := bytes.Clone(frame.Payload)
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
	cli.WriteCommandUsage(w,
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
	cli.WriteCommandUsage(w,
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
	cli.WriteCommandUsage(w,
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
