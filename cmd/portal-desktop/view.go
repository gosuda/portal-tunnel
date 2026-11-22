package main

import (
	"fmt"

	"github.com/ironpark/ggui"
	gguiruntime "github.com/ironpark/ggui/runtime"
	"github.com/ironpark/ggui/ui"
	"github.com/ironpark/ggui/widget"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const (
	notRunningText = "The Portal agent is not running."
	agentGuideURL  = "https://gosuda.github.io/portal-tunnel/portal-agent#create-a-config"
)

// view builds the window from the model. The forms live in dialogs above the
// tunnel list, so the list can follow every answer of the agent without
// taking a draft or the focus from the user.
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
		ggui.View(m.Problem, v.problemNotice),
		widget.Expanded(widget.Scroll(ggui.View(m.Status, v.tunnels))),
	).Space(1.5).Stretch()
	return widget.Stack(
		widget.Box(page).Pad(24),
		v.addDialog(),
		v.settingsDialog(),
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
	text := msg + " The list shows the last state the agent reported."
	alert := ui.Alert("Portal agent unavailable", text).Destructive()
	if msg != notRunningText {
		return alert
	}
	return widget.Column(
		alert,
		widget.Row(
			ui.Caption("Start it in a terminal:"),
			ui.Mono(startCommand),
			ui.Button("Copy command", func() { v.copy(startCommand) }).Outline().Size(ui.ButtonSmall),
			ui.Button("Agent guide", func() { v.open(agentGuideURL) }).Ghost().Size(ui.ButtonSmall),
		).Space(1).Align(widget.AlignCenter),
		ui.Caption("The agent reads its config file; the guide shows how to create one."),
	).Space(0.75).Stretch()
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
	return widget.Column(cards...).Space(1.5).Stretch()
}

func (v *view) tunnelCard(tunnel agent.AgentTunnelStatus) ggui.Widget {
	label := tunnel.Label()
	settings := ui.Button("Settings", func() { v.m.openSettings(tunnel) }).Outline().Size(ui.ButtonSmall).Name("Settings for " + label).BindDisabled(v.blocked)
	remove := ui.Button("Delete", func() { v.m.Deleting.Set(tunnel.ID) }).Outline().Size(ui.ButtonSmall).Name("Delete " + label).BindDisabled(v.blocked)
	rows := []ggui.Widget{
		widget.Row(ui.Heading(label), stateBadge(tunnel.State), widget.Spacer(), settings, remove).Space(1).Align(widget.AlignCenter),
		ui.Caption(tunnelDetails(tunnel)),
	}
	if tunnel.LastError != "" {
		rows = append(rows, ui.Alert("Tunnel error", tunnel.LastError).Destructive())
	}
	if tunnel.AuthProviderError != "" {
		rows = append(rows, ui.Alert("Sign-in provider check failed", tunnel.AuthProviderError).Destructive())
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
	v.allowWhen(disconnect, running)
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
		} else if relay.TCPAddr != "" {
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
	return widget.Column(rows...).Space(0.5).Stretch()
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

func (v *view) addDialog() ggui.Widget {
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
	return ui.Dialog(v.m.Adding, form).
		Title("Expose a local service").
		Description("The agent keeps the tunnel running after this window closes.").
		Footer(
			ui.Button("Cancel", func() { v.m.Adding.Set(false) }).Outline(),
			ui.Button("Expose", func() { v.m.addTunnel(v.h) }).BindDisabled(v.blocked),
		).
		Width(480)
}

func (v *view) settingsDialog() ggui.Widget {
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
	return ui.Dialog(open, form).
		Title("Tunnel settings").
		Description("The agent applies these to the running tunnel and keeps them in its config.").
		Footer(
			ui.Button("Cancel", func() { v.m.Editing.Set("") }).Outline(),
			ui.Button("Save", func() { v.m.saveSettings(v.h) }).BindDisabled(v.blocked),
		).
		Width(480)
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
