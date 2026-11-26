package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/ironpark/ggui"
	gguiruntime "github.com/ironpark/ggui/runtime"
	"github.com/ironpark/ggui/ui"
	uitheme "github.com/ironpark/ggui/ui/theme"
	"github.com/ironpark/ggui/widget"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const (
	notRunningText = "The Portal agent is not running."
	// adminText is why a desktop that is not elevated cannot read the control
	// endpoint of an agent that runs as a Windows service.
	adminText     = "Only administrators can connect to the Portal agent when it runs as a Windows service. Run Portal Desktop as an administrator."
	agentGuideURL = "https://gosuda.github.io/portal-tunnel/portal-agent"
)

// view builds the window from the model. The forms live in sheets above the
// tunnel list, so the list can follow every answer of the agent without
// taking a draft or the focus from the user. A sheet is as tall as the
// window and scrolls its form above its actions, so the actions stay in
// view at the smallest window size.
type view struct {
	m       *model
	h       ggui.Host
	toaster *ui.ToasterWidget
	// blocked holds back what asks the agent for something while it is out
	// of reach or still answering an earlier request.
	blocked ggui.Readable[bool]
}

func build(m *model) ggui.Widget {
	v := &view{m: m, h: ggui.UseHost(), toaster: ui.NewToaster()}
	ggui.OnCleanup(v.toaster.Close)
	v.blocked = ggui.Derived(func() bool { return m.Connection.Get() != connected || m.Busy.Get() })
	page := widget.Column(
		v.header(),
		ggui.View(m.AgentError, v.agentNotice),
		ggui.View(m.OtherConfig, v.otherConfigNotice),
		ggui.View(m.Problem, v.problemNotice),
		widget.Expanded(scroll(ggui.View(m.Status, v.tunnels))),
	).Space(1.5).Stretch()
	return widget.Stack(
		widget.Box(page).Pad(24),
		ggui.View(m.SettingUp, v.setupSheet),
		v.addSheet(),
		v.settingsSheet(),
		ggui.View(m.Deleting, v.deleteDialog),
		v.toaster,
	).Expand()
}

func (v *view) header() ggui.Widget {
	return widget.Row(
		ui.Title("Portal"),
		ggui.View(v.m.Connection, connectionBadge),
		widget.Spacer(),
		ui.Button("Expose a service", v.m.openAdd),
	).Space(1).Align(widget.AlignCenter)
}

func connectionBadge(c connection) ggui.Widget {
	switch c {
	case connected:
		return ui.Badge("Agent connected")
	case unreachable:
		return ui.Badge("Agent unavailable").Destructive()
	default:
		return ui.Badge("Connecting…").Secondary()
	}
}

func (v *view) agentNotice(msg string) ggui.Widget {
	if msg == "" {
		return widget.Box()
	}
	text := msg
	if v.m.answered {
		text += " The list shows the last state the agent reported."
	}
	alert := ui.Alert("Portal agent unavailable", text).Destructive()
	if msg != notRunningText {
		return alert
	}
	var actions []ggui.Widget
	hint := "Portal Desktop did not find the portal CLI. Start the agent in a terminal:"
	if v.m.cli != "" {
		actions = append(actions, ui.Button("Set up and start", v.m.openSetup).Size(ui.ButtonSmall).BindDisabled(v.m.Busy))
		hint = "Or start it in a terminal:"
	}
	actions = append(actions,
		ui.Caption(hint),
		ui.Mono(startCommand),
		ui.Button("Copy command", func() { v.copy(startCommand) }).Outline().Size(ui.ButtonSmall),
		ui.Button("Agent guide", func() { v.open(agentGuideURL) }).Ghost().Size(ui.ButtonSmall),
	)
	// The actions flow onto more lines in a narrow window instead of
	// squeezing a button narrower than its label.
	return widget.Column(alert, widget.Wrap(actions...).Space(1).Align(widget.AlignCenter)).Space(0.75).Stretch()
}

// sheetSize is the width of the sheets, which shrink to fit a smaller window.
const sheetSize = 440

// barGutter is the room at the right of scrolled content for the scroll
// bar, which the theme draws 8 px wide over the right edge of a scroll.
const barGutter = 12

// scroll scrolls content with the scroll bar beside it, not over the right
// edge of a field or a card.
func scroll(content ggui.Widget) *widget.ScrollWidget {
	return widget.Scroll(widget.Box(content).Pad(0, barGutter, 0, 0))
}

// setupSheet asks before the desktop creates the agent config or installs
// the agent as a service of the OS, and says what each step does.
func (v *view) setupSheet(open bool) ggui.Widget {
	if !open {
		return widget.Box()
	}
	config := "Portal Desktop uses the agent config at " + v.m.configPath + "."
	if _, err := os.Stat(v.m.configPath); errors.Is(err, os.ErrNotExist) {
		config = "Portal Desktop creates an agent config without tunnels at " + v.m.configPath + ". The agent keeps the tunnels that you add there."
	}
	body := widget.Column(
		widget.Text(config),
		widget.Text("Then Portal Desktop runs "+startCommand+". "+serviceScope()),
		widget.Text("The agent and its tunnels keep running after you quit Portal Desktop. To stop the agent and keep it from starting again, run portal agent stop."),
		ggui.View(v.m.FormError, formError),
	).Space(1).Stretch()
	return ui.Sheet(v.m.SettingUp, scroll(body)).
		Title("Set up the Portal agent").
		Footer(
			ui.Button("Install and start", func() { v.m.startAgent(v.h) }).BindDisabled(v.m.Busy),
			ui.Button("Cancel", func() { v.m.SettingUp.Set(false) }).Outline(),
		).
		Size(sheetSize)
}

// serviceScope is what portal agent run installs on this OS, and the rights
// that it needs.
func serviceScope() string {
	switch runtime.GOOS {
	case "darwin":
		return "It installs the agent as a launchd agent of your user, which starts when you log in and restarts the agent if it stops."
	case "windows":
		return "It installs the agent as a Windows service, which starts with Windows. This needs administrator rights. " + adminText
	default:
		return "It installs the agent as a systemd service of your user, which starts when you log in. As root, it installs a system service."
	}
}

// otherConfigNotice says that a later launch asked for an agent that this
// window does not show, because only one Portal Desktop runs at a time.
func (v *view) otherConfigNotice(path string) ggui.Widget {
	if path == "" {
		return widget.Box()
	}
	dismiss := ui.Button("Dismiss", func() { v.m.OtherConfig.Set("") }).Outline().Size(ui.ButtonSmall)
	text := "This window shows the agent of " + v.m.configPath + ". To open " + path + ", quit Portal Desktop and open it again."
	return ui.Alert("Portal Desktop is already open", text).Action(dismiss)
}

func (v *view) problemNotice(msg string) ggui.Widget {
	if msg == "" {
		return widget.Box()
	}
	dismiss := ui.Button("Dismiss", func() { v.m.Problem.Set("") }).Outline().Size(ui.ButtonSmall)
	return ui.Alert("The agent refused a request", msg).Destructive().Action(dismiss)
}

func (v *view) tunnels(status agent.AgentStatusResponse) ggui.Widget {
	if len(status.Tunnels) == 0 {
		return ui.Empty("No tunnels", "Expose a local service to publish it through Portal relays.")
	}
	cards := make([]ggui.Widget, 0, len(status.Tunnels))
	for _, tunnel := range status.Tunnels {
		cards = append(cards, v.tunnelCard(tunnel))
	}
	return widget.Column(cards...).Space(2).Stretch()
}

func (v *view) tunnelCard(tunnel agent.AgentTunnelStatus) ggui.Widget {
	label := tunnel.Label()
	settings := ui.Button("Settings", func() { v.m.openSettings(tunnel) }).Outline().Size(ui.ButtonSmall).Name("Settings for " + label).BindDisabled(v.blocked)
	remove := ui.Button("Delete", func() { v.m.Deleting.Set(tunnel.ID) }).Outline().Size(ui.ButtonSmall).Name("Delete " + label).BindDisabled(v.blocked)
	rows := []ggui.Widget{
		widget.Row(
			// The name gives way to the buttons: a long one is cut to one
			// line ending in an ellipsis instead of pushing Settings and
			// Delete out of the card.
			widget.Expanded(widget.Row(widget.Flexible(ui.Heading(label).MaxLines(1)), stateBadge(tunnel.State)).Space(1).Align(widget.AlignCenter)),
			settings, remove,
		).Space(1).Align(widget.AlignCenter),
		ui.Caption(tunnelDetails(tunnel)),
	}
	if tunnel.LastError != "" {
		rows = append(rows, ui.Caption("Tunnel error: "+tunnel.LastError).Color(uitheme.Destructive))
	}
	if tunnel.AuthProviderError != "" {
		rows = append(rows, ui.Caption("Sign-in provider check failed: "+tunnel.AuthProviderError).Color(uitheme.Destructive))
	}
	if len(tunnel.Relays) == 0 {
		rows = append(rows, ui.Caption("No relay carries this tunnel yet."))
	}
	for _, relay := range tunnel.Relays {
		rows = append(rows, ui.Divider(), v.relayRow(tunnel, relay))
	}
	return ui.Card(widget.Column(rows...).Space(1).Stretch()).Pad(16)
}

func tunnelDetails(tunnel agent.AgentTunnelStatus) string {
	discovery := "discovery off"
	if tunnel.Discovery {
		discovery = "discovery on"
	}
	details := fmt.Sprintf("Forwards to %s · %s", tunnel.TargetSummary(), discovery)
	if tunnel.MaxActiveRelays > 0 {
		details += fmt.Sprintf(" · up to %d relays", tunnel.MaxActiveRelays)
	}
	return details
}

func stateBadge(state string) ggui.Widget {
	switch state {
	case "running":
		return ui.Badge("running")
	case "starting":
		return ui.Badge("starting").Secondary()
	case "error":
		return ui.Badge("error").Destructive()
	default:
		return ui.Badge(state).Outline()
	}
}

func modeBadge(relay agent.AgentRelayStatus) ggui.Widget {
	mode := relay.Mode()
	switch mode {
	case "direct":
		return ui.Badge(mode)
	case "waiting", "connecting...", "legacy TLS":
		return ui.Badge(mode).Secondary()
	case "refused", "failed":
		return ui.Badge(mode).Destructive()
	default:
		return ui.Badge(mode).Outline()
	}
}

// relayRow shows one relay of a tunnel: how it carries the tunnel, where
// clients reach it, and why it does not when it does not. An HTTP endpoint
// can be opened in a browser; a TCP one is an address to connect to.
func (v *view) relayRow(tunnel agent.AgentTunnelStatus, relay agent.AgentRelayStatus) ggui.Widget {
	running := tunnel.State == "running"
	connect := ui.Button("Connect", func() { v.m.connectRelay(v.h, tunnel.ID, relay.RelayURL) }).
		Outline().Size(ui.ButtonSmall).Name("Connect " + relay.RelayURL)
	v.allowWhen(connect, running && relay.State != sdk.RelayReady && relay.State != sdk.RelayConnecting)
	disconnect := ui.Button("Disconnect", func() { v.m.disconnectRelay(v.h, tunnel.ID, relay.RelayURL) }).
		Outline().Size(ui.ButtonSmall).Name("Disconnect " + relay.RelayURL)
	v.allowWhen(disconnect, running && relay.State != agent.RelayDisconnected)
	rows := []ggui.Widget{
		widget.Row(modeBadge(relay), widget.Expanded(ui.Mono(relay.RelayURL).Ellipsis()), connect, disconnect).Space(1).Align(widget.AlignCenter),
	}
	if relay.State == sdk.RelayReady {
		if publicURL := relay.URL(); publicURL != "" {
			rows = append(rows, widget.Row(
				widget.Expanded(ui.Mono(publicURL).Selectable()),
				ui.Button("Copy", func() { v.copy(publicURL) }).Ghost().Size(ui.ButtonSmall).Name("Copy "+publicURL),
				ui.Button("Open", func() { v.open(publicURL) }).Ghost().Size(ui.ButtonSmall).Name("Open "+publicURL),
			).Space(1).Align(widget.AlignCenter))
		}
		if relay.TCPAddr != "" {
			rows = append(rows, widget.Row(
				ui.Caption("TCP"),
				widget.Expanded(ui.Mono(relay.TCPAddr).Selectable()),
				ui.Button("Copy", func() { v.copy(relay.TCPAddr) }).Ghost().Size(ui.ButtonSmall).Name("Copy "+relay.TCPAddr),
			).Space(1).Align(widget.AlignCenter))
		}
	}
	for _, note := range relayNotes(relay) {
		rows = append(rows, ui.Caption(note))
	}
	return widget.Column(rows...).Space(1).Stretch()
}

// relayNotes say why a relay does not carry the tunnel, in the agent's own
// words where it has them.
func relayNotes(relay agent.AgentRelayStatus) []string {
	var notes []string
	switch relay.Approval {
	case sdk.RelayApprovalPending:
		notes = append(notes, "Waiting for the relay operator to approve this tunnel.")
	case sdk.RelayApprovalRefused:
		notes = append(notes, "The relay operator refused this tunnel.")
	}
	if relay.Failure != sdk.RelayFailureNone {
		notes = append(notes, "Relay failure: "+string(relay.Failure))
	}
	if relay.CertificateError != "" {
		notes = append(notes, "Certificate: "+relay.CertificateError)
	}
	return notes
}

// allowWhen leaves button to what blocked says while the relay's state
// allows its action, as the terminal dashboard does, and disables it
// otherwise.
func (v *view) allowWhen(button *ui.ButtonWidget, allowed bool) {
	if allowed {
		button.BindDisabled(v.blocked)
	} else {
		button.Disabled(true)
	}
}

func (v *view) copy(text string) {
	v.h.Clipboard().Write(text)
	v.toaster.Push(ui.Toast("Copied", text).Success())
}

// open hands an http or https URL, as AgentRelayStatus.URL gives it, to the
// system browser.
func (v *view) open(publicURL string) {
	if err := gguiruntime.OpenURL(publicURL); err != nil {
		v.toaster.Push(ui.Toast("Could not open the browser", err.Error()).Error())
	}
}

func (v *view) addSheet() ggui.Widget {
	d := v.m.Draft
	target := d.Field(func(t *tunnelDraft) *string { return &t.Target })
	name := d.Field(func(t *tunnelDraft) *string { return &t.Name })
	relays := d.Field(func(t *tunnelDraft) *string { return &t.Relays })
	discovery := d.Field(func(t *tunnelDraft) *bool { return &t.Discovery })
	maxRelays := d.Field(func(t *tunnelDraft) *string { return &t.MaxRelays })
	form := widget.Column(
		ui.Field("Local service", ui.TextField(target).Placeholder("3000 or 127.0.0.1:8080").Name("Local service")).
			Help("A port on this machine, or a host:port the agent can reach."),
		ui.Field("Name", ui.TextField(name).Placeholder("my-app").Name("Name")).
			Help("Names the tunnel and its public address."),
		ui.Field("Relays", ui.TextField(relays).Placeholder("https://relay.example.com").Name("Relays")).
			Help("Relay URLs to use, separated by commas."),
		ui.Switch(discovery, "Discover more relays"),
		ui.Field("Max relays", ui.TextField(maxRelays).Placeholder("agent default").Name("Max relays")).
			Help("How many relays carry the tunnel at once."),
		ggui.View(v.m.FormError, formError),
	).Space(1.25).Stretch()
	return ui.Sheet(v.m.Adding, scroll(form)).
		Title("Expose a local service").
		Description("The agent keeps the tunnel running after this window closes.").
		Footer(
			ui.Button("Expose", func() { v.m.addTunnel(v.h) }).BindDisabled(v.blocked),
			ui.Button("Cancel", func() { v.m.Adding.Set(false) }).Outline(),
		).
		Size(sheetSize)
}

func (v *view) settingsSheet() ggui.Widget {
	s := v.m.Settings
	maxRelays := s.Field(func(d *settingsDraft) *string { return &d.MaxRelays })
	description := s.Field(func(d *settingsDraft) *string { return &d.Description })
	tags := s.Field(func(d *settingsDraft) *string { return &d.Tags })
	hide := s.Field(func(d *settingsDraft) *bool { return &d.Hide })
	open := ggui.Bind(func() bool { return v.m.Editing.Get() != "" }, func(open bool) {
		if !open {
			v.m.Editing.Set("")
		}
	})
	form := widget.Column(
		ui.Field("Max relays", ui.TextField(maxRelays).Name("Max relays")).
			Help("How many relays carry the tunnel at once."),
		ui.Field("Description", ui.TextField(description).Name("Description")).
			Help("Shown in the relay's service list."),
		ui.Field("Tags", ui.TextField(tags).Name("Tags")).
			Help("Separated by commas."),
		ui.Switch(hide, "Hide from relay service lists"),
		ggui.View(v.m.FormError, formError),
	).Space(1.25).Stretch()
	return ui.Sheet(open, scroll(form)).
		Title("Tunnel settings").
		Description("The agent applies these to the running tunnel and keeps them in its config.").
		Footer(
			ui.Button("Save", func() { v.m.saveSettings(v.h) }).BindDisabled(v.blocked),
			ui.Button("Cancel", func() { v.m.Editing.Set("") }).Outline(),
		).
		Size(sheetSize)
}

func formError(msg string) ggui.Widget {
	if msg == "" {
		return widget.Box()
	}
	return ui.Alert("Not done", msg).Destructive()
}

func (v *view) deleteDialog(id string) ggui.Widget {
	if id == "" {
		return widget.Box()
	}
	tunnel, ok := findTunnel(ggui.Peek(v.m.Status), id)
	if !ok {
		tunnel = agent.AgentTunnelStatus{ID: id}
	}
	open := ggui.Bind(func() bool { return v.m.Deleting.Get() != "" }, func(open bool) {
		if !open {
			v.m.Deleting.Set("")
		}
	})
	return ui.AlertDialog(open, "Delete "+tunnel.Label()+"?", "The agent stops the tunnel and removes it from its config. Its public address stops answering.").
		Confirm("Delete", func() { v.m.deleteTunnel(v.h, tunnel) }).
		Destructive()
}
