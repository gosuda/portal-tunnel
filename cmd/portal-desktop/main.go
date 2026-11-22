// Command portal-desktop is the desktop client of the Portal agent: it shows
// the tunnels the agent runs and asks the agent, through its local Control
// API, to add, change and remove them. The agent owns every tunnel, so
// closing or quitting the desktop leaves them running.
package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ironpark/ggui"
	gguiruntime "github.com/ironpark/ggui/runtime"
	"github.com/ironpark/ggui/ui/icons"
	uitheme "github.com/ironpark/ggui/ui/theme"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
)

// appID names the app to the desktop: its bundle, its single instance, its
// notifications and its saved window placement. It matches app.id in
// ggui.toml, and must stay the same across releases.
const appID = "org.gosuda.portal.desktop"

//go:embed icon.svg
var iconSVG []byte

func main() {
	fs := flag.NewFlagSet("portal-desktop", flag.ExitOnError)
	configPath := fs.String("config", "", "Portal agent TOML config path (default: the agent's default config)")
	stateDir := fs.String("state-dir", "", "Portal agent state directory (default: the one the config names)")
	hidden := fs.Bool("hidden", false, "Start in the tray without showing the window, where the platform has a tray")
	_ = fs.Parse(os.Args[1:])
	if err := run(*configPath, *stateDir, *hidden); err != nil {
		log.Fatal(err)
	}
}

func run(configPath, stateDir string, hidden bool) error {
	var configErr error
	if stateDir == "" {
		stateDir, configErr = agent.StateDir(configPath)
	}
	m := newModel(stateDir)
	if configErr != nil {
		m.Connection.Set(unreachable)
		m.AgentError.Set(fmt.Sprintf("Could not read the agent config: %v", configErr))
	}
	app := ggui.New(ggui.Config{
		Title:     "Portal",
		Width:     920,
		Height:    680,
		MinWidth:  560,
		MinHeight: 420,
		Resizable: true,
		Remember:  "main",
	}, func() ggui.Widget { return build(m) })
	err := app.SingleInstance(appID, func(gguiruntime.Launch) { app.ShowFromTray() })
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
		uitheme.Bind(ggui.SystemDark(), uitheme.Dark(), uitheme.Default())
		if configErr == nil {
			m.start(app)
		}
		if hidden && tray {
			app.HideToTray()
		}
	})
	return app.Run()
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
