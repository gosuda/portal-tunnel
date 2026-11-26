// Command portal-desktop is the desktop client of the Portal agent: it shows
// the tunnels the agent runs and asks the agent, through its local Control
// API, to add, change and remove them. The agent owns every tunnel, so
// closing or quitting the desktop leaves them running.
package main

import (
	"cmp"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ironpark/ggui"
	gguiruntime "github.com/ironpark/ggui/runtime"
	"github.com/ironpark/ggui/ui/icons"
	uitheme "github.com/ironpark/ggui/ui/theme"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent/service"
	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/installer"
)

// appID names the app to the desktop: its bundle, its single instance, its
// notifications and its saved window placement. It matches app.id in
// ggui.toml, and must stay the same across releases.
const appID = "org.gosuda.portal.desktop"

// The smallest window size. The forms keep their actions in view at it.
const (
	minWidth  = 560
	minHeight = 420
)

//go:embed icon.svg
var iconSVG []byte

//go:embed theme.css
var themeCSS string

// options are the flags of portal-desktop, of the first launch and of each
// later one.
type options struct {
	configPath string
	stateDir   string
	hidden     bool
}

func parseOptions(args []string, out io.Writer, handling flag.ErrorHandling) (options, error) {
	var o options
	fs := flag.NewFlagSet("portal-desktop", handling)
	fs.SetOutput(out)
	fs.StringVar(&o.configPath, "config", "", "Portal agent TOML config path (default: the agent's default config)")
	fs.StringVar(&o.stateDir, "state-dir", "", "Portal agent state directory (default: the one the config names)")
	fs.BoolVar(&o.hidden, "hidden", false, "Start in the tray without showing the window, where the platform has a tray")
	err := fs.Parse(args)
	return o, err
}

func main() {
	o, _ := parseOptions(os.Args[1:], os.Stderr, flag.ExitOnError)
	if err := run(o); err != nil {
		log.Fatal(err)
	}
}

func run(o options) error {
	light, dark, err := uitheme.FromCSS(themeCSS)
	if err != nil {
		return fmt.Errorf("read the theme: %w", err)
	}
	configPath, err := filepath.Abs(cmp.Or(o.configPath, service.DefaultConfigPath()))
	if err != nil {
		return err
	}
	var configErr error
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir, configErr = agent.StateDir(configPath)
	} else if stateDir, err = filepath.Abs(stateDir); err != nil {
		return err
	}
	var cli string
	if exe, err := os.Executable(); err == nil {
		cli, _ = installer.CLI(exe)
	}
	m := newModel(stateDir, configPath, cli)
	// Without its state directory the desktop cannot find the agent, so it
	// does not poll; it reads the config again only when it is reopened.
	if configErr != nil {
		m.Connection.Set(unreachable)
		m.AgentError.Set(fmt.Sprintf("Could not read the agent config: %s. Quit and reopen Portal Desktop after you fix this.",
			strings.TrimSuffix(agentErrorText(configErr), ".")))
	}
	app := ggui.New(ggui.Config{
		Title:     "Portal",
		Width:     920,
		Height:    680,
		MinWidth:  minWidth,
		MinHeight: minHeight,
		Resizable: true,
		Remember:  "main",
	}, func() ggui.Widget { return build(m) })
	err = app.SingleInstance(appID, func(l gguiruntime.Launch) {
		app.ShowFromTray()
		if other := otherAgent(l, configPath, stateDir); other != "" {
			m.OtherConfig.Set(other)
		}
	})
	if errors.Is(err, gguiruntime.ErrRunning) {
		return nil
	}
	if err != nil {
		log.Printf("single instance: %v", err)
	}
	tray := ggui.TraySupported()
	if tray {
		addTray(app)
	}
	app.Setup(func() {
		uitheme.Bind(ggui.SystemDark(), dark, light)
		if configErr == nil {
			m.start(app)
		}
		if o.hidden && tray {
			app.HideToTray()
		}
	})
	return app.Run()
}

// otherAgent is the config or the state directory that a later launch l
// names, when this window shows another one. It is "" when l names neither,
// or names those of this window.
func otherAgent(l gguiruntime.Launch, configPath, stateDir string) string {
	o, err := parseOptions(l.Args, io.Discard, flag.ContinueOnError)
	if err != nil {
		return ""
	}
	for _, path := range []struct{ named, open string }{{o.configPath, configPath}, {o.stateDir, stateDir}} {
		if path.named == "" {
			continue
		}
		named := path.named
		if !filepath.IsAbs(named) {
			named = filepath.Join(l.Dir, named)
		}
		if filepath.Clean(named) != filepath.Clean(path.open) {
			return named
		}
	}
	return ""
}

// addTray keeps the desktop in the tray while its window is closed, so its
// notifications keep coming. Quitting it from the tray leaves the agent and
// its tunnels running.
func addTray(app *ggui.App) {
	cfg := ggui.TrayConfig{
		Template: true,
		Tooltip:  "Portal",
		Menu: []ggui.MenuItem{
			ggui.MenuAction("Open Portal", "", app.ShowFromTray),
			ggui.MenuSeparator(),
			ggui.MenuAction("Quit Portal Desktop", "", app.Quit),
		},
	}
	if icon, err := icons.Parse(iconSVG); err == nil {
		cfg.Icon = icon.Image(64)
	}
	app.AddTray(cfg)
	app.OnCloseRequest(func() bool {
		app.HideToTray()
		return false
	})
	app.OnReopen(app.ShowFromTray)
}
