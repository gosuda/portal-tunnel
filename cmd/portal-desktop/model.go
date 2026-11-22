package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ironpark/ggui"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/sdk"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	pollInterval = 2 * time.Second
	// requestTimeout covers portal agent run, which waits up to 30 s for the
	// agent it starts to answer.
	requestTimeout = 45 * time.Second
	startCommand   = "portal agent run"
)

// connection is what the desktop knows of the agent.
type connection int

const (
	connecting connection = iota
	connected
	unreachable
)

// model is the desktop's state. The agent owns every tunnel: the model only
// keeps its last answer and the drafts of what the user asks of it. Its
// signals belong to the UI thread; agent calls run on goroutines and post
// their results back.
type model struct {
	stateDir string
	// configPath is the agent config that the setup creates when it is
	// missing and gives to portal agent run.
	configPath string
	// cli is the portal CLI that starts the agent, or "" when the desktop
	// found none.
	cli string

	Status     *ggui.StateValue[agent.AgentStatusResponse]
	Connection *ggui.StateValue[connection]
	AgentError *ggui.StateValue[string]
	Busy       *ggui.StateValue[bool]
	Problem    *ggui.StateValue[string]

	SettingUp *ggui.StateValue[bool]

	Adding    *ggui.StateValue[bool]
	Draft     *ggui.StateValue[tunnelDraft]
	FormError *ggui.StateValue[string]

	Editing  *ggui.StateValue[string]
	Settings *ggui.StateValue[settingsDraft]
	Deleting *ggui.StateValue[string]
}

func newModel(stateDir, configPath, cli string) *model {
	return &model{
		stateDir:   stateDir,
		configPath: configPath,
		cli:        cli,
		// Polls repeat the same answer; only a different one repaints.
		Status:     ggui.State(agent.AgentStatusResponse{}).WithEqual(sameStatus),
		Connection: ggui.State(connecting),
		AgentError: ggui.State(""),
		Busy:       ggui.State(false),
		Problem:    ggui.State(""),
		SettingUp:  ggui.State(false),
		Adding:     ggui.State(false),
		Draft:      ggui.State(newTunnelDraft()),
		FormError:  ggui.State(""),
		Editing:    ggui.State(""),
		Settings:   ggui.State(settingsDraft{}),
		Deleting:   ggui.State(""),
	}
}

func sameStatus(a, b agent.AgentStatusResponse) bool { return reflect.DeepEqual(a, b) }

// start polls the agent until the host's owner is cleaned up. The agent may
// stop, start or restart at any time; each answer, or its absence, replaces
// what the window shows.
func (m *model) start(h ggui.Host) {
	ctx, cancel := context.WithCancel(context.Background())
	ggui.OnCleanup(cancel)
	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			status, err := agent.Status(ctx, m.stateDir)
			if ctx.Err() != nil {
				return
			}
			h.Post(func() { m.apply(h, status, err) })
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// apply takes an answer of the agent, or the error of asking it. Without an
// answer the last status stays on screen, marked as out of date, so the user
// keeps their place and drafts until the agent is back.
func (m *model) apply(h ggui.Host, status agent.AgentStatusResponse, err error) {
	previous := ggui.Peek(m.Connection)
	if err != nil {
		m.Connection.Set(unreachable)
		m.AgentError.Set(agentErrorText(err))
		if previous == connected {
			notify(h, ggui.Notification{ID: "agent", Title: "Portal agent unavailable", Body: agentErrorText(err)})
		}
		return
	}
	last := ggui.Peek(m.Status)
	m.Connection.Set(connected)
	m.AgentError.Set("")
	m.Status.Set(status)
	if previous == connecting {
		return
	}
	if previous == unreachable {
		h.RemoveNotification("agent")
	}
	for _, n := range statusNotifications(last, status) {
		notify(h, n)
	}
}

// notify shows n where the platform has notifications; elsewhere the window
// already shows the same state.
func notify(h ggui.Host, n ggui.Notification) {
	if err := h.Notify(n); err != nil && !errors.Is(err, ggui.ErrNotificationsUnavailable) && !errors.Is(err, ggui.ErrNotificationsDenied) {
		log.Printf("notification %q: %v", n.ID, err)
	}
}

func agentErrorText(err error) string {
	if errors.Is(err, agent.ErrNotRunning) {
		return notRunningText
	}
	if runtime.GOOS == "windows" && errors.Is(err, fs.ErrPermission) {
		return adminText
	}
	return err.Error()
}

// statusNotifications are the changes between two answers of the agent that
// are worth a notification: a tunnel that failed or recovered, and a relay
// that asks for approval or refused it. A later notification about the same
// tunnel or relay replaces the earlier one.
func statusNotifications(before, after agent.AgentStatusResponse) []ggui.Notification {
	var out []ggui.Notification
	for _, tunnel := range after.Tunnels {
		old, known := findTunnel(before, tunnel.ID)
		label := tunnel.Label()
		switch {
		case tunnel.State == "error" && (!known || old.State != "error"):
			out = append(out, ggui.Notification{ID: "tunnel/" + tunnel.ID, Title: label + " stopped", Body: tunnel.LastError, Data: tunnel.ID})
		case known && old.State == "error" && tunnel.State == "running":
			out = append(out, ggui.Notification{ID: "tunnel/" + tunnel.ID, Title: label + " is running again", Data: tunnel.ID})
		}
		for _, relay := range tunnel.Relays {
			oldRelay, _ := findRelay(old, relay.RelayURL)
			if relay.Approval == oldRelay.Approval {
				continue
			}
			id := "relay/" + tunnel.ID + "/" + relay.RelayURL
			switch relay.Approval {
			case sdk.RelayApprovalPending:
				out = append(out, ggui.Notification{ID: id, Title: label + " waits for approval", Body: relay.RelayURL + " carries the tunnel once its operator approves it.", Data: tunnel.ID})
			case sdk.RelayApprovalRefused:
				out = append(out, ggui.Notification{ID: id, Title: relay.RelayURL + " refused " + label, Data: tunnel.ID})
			}
		}
	}
	return out
}

func findTunnel(status agent.AgentStatusResponse, id string) (agent.AgentTunnelStatus, bool) {
	for _, tunnel := range status.Tunnels {
		if tunnel.ID == id {
			return tunnel, true
		}
	}
	return agent.AgentTunnelStatus{}, false
}

func findRelay(tunnel agent.AgentTunnelStatus, relayURL string) (agent.AgentRelayStatus, bool) {
	for _, relay := range tunnel.Relays {
		if relay.RelayURL == relayURL {
			return relay, true
		}
	}
	return agent.AgentRelayStatus{}, false
}

// request runs call against the agent off the UI thread and then reads the
// status again, so the window shows what the call changed. A refused call
// goes to failed; done runs once the agent accepted it.
func (m *model) request(h ggui.Host, call func(context.Context) error, failed func(error), done func()) {
	if ggui.Peek(m.Busy) {
		return
	}
	m.Busy.Set(true)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		err := call(ctx)
		var status agent.AgentStatusResponse
		var statusErr error
		if err == nil {
			status, statusErr = agent.Status(ctx, m.stateDir)
		}
		h.Post(func() {
			m.Busy.Set(false)
			if err != nil {
				failed(err)
				return
			}
			m.apply(h, status, statusErr)
			if done != nil {
				done()
			}
		})
	}()
}

func (m *model) fail(action string) func(error) {
	return func(err error) { m.Problem.Set(action + ": " + agentErrorText(err)) }
}

func (m *model) failForm(err error) { m.FormError.Set(agentErrorText(err)) }

func (m *model) openSetup() {
	m.FormError.Set("")
	m.SettingUp.Set(true)
}

// startAgent sets up and starts the agent after the user agreed to it in the
// setup dialog. It creates the config when there is none, then runs
// portal agent run, which installs the agent as a service of the OS and waits
// until it answers. The service runs the agent, so the agent and its tunnels
// outlive the desktop.
func (m *model) startAgent(h ggui.Host) {
	m.FormError.Set("")
	m.request(h, func(ctx context.Context) error {
		if err := agent.CreateConfig(m.configPath); err != nil {
			return fmt.Errorf("create the agent config: %w", err)
		}
		out, err := exec.CommandContext(ctx, m.cli, "agent", "run", "--config", m.configPath).CombinedOutput()
		if msg := strings.TrimSpace(string(out)); err != nil && msg != "" {
			return fmt.Errorf("%s: %s", startCommand, msg)
		}
		return err
	}, m.failForm, func() { m.SettingUp.Set(false) })
}

func (m *model) openAdd() {
	m.FormError.Set("")
	m.Adding.Set(true)
}

func (m *model) addTunnel(h ggui.Host) {
	req, err := ggui.Peek(m.Draft).request()
	if err != nil {
		m.FormError.Set(err.Error())
		return
	}
	m.FormError.Set("")
	m.request(h, func(ctx context.Context) error { return agent.AddTunnel(ctx, m.stateDir, req) }, m.failForm, func() {
		m.Adding.Set(false)
		m.Draft.Set(newTunnelDraft())
	})
}

func (m *model) openSettings(tunnel agent.AgentTunnelStatus) {
	m.FormError.Set("")
	m.Settings.Set(settingsOf(tunnel))
	m.Editing.Set(tunnel.ID)
}

func (m *model) saveSettings(h ggui.Host) {
	id := ggui.Peek(m.Editing)
	req, err := ggui.Peek(m.Settings).request()
	if err != nil {
		m.FormError.Set(err.Error())
		return
	}
	m.FormError.Set("")
	m.request(h, func(ctx context.Context) error { return agent.UpdateTunnel(ctx, m.stateDir, id, req) }, m.failForm, func() {
		m.Editing.Set("")
	})
}

func (m *model) deleteTunnel(h ggui.Host, tunnel agent.AgentTunnelStatus) {
	m.request(h, func(ctx context.Context) error { return agent.DeleteTunnel(ctx, m.stateDir, tunnel.ID) }, m.fail("Could not delete "+tunnel.Label()), nil)
}

func (m *model) connectRelay(h ggui.Host, id, relayURL string) {
	m.request(h, func(ctx context.Context) error { return agent.ConnectRelay(ctx, m.stateDir, id, relayURL) }, m.fail("Could not connect "+relayURL), nil)
}

func (m *model) disconnectRelay(h ggui.Host, id, relayURL string) {
	m.request(h, func(ctx context.Context) error { return agent.DisconnectRelay(ctx, m.stateDir, id, relayURL) }, m.fail("Could not disconnect "+relayURL), nil)
}

// tunnelDraft is the form that exposes a local service.
type tunnelDraft struct {
	Name      string
	Target    string
	Relays    string
	Discovery bool
	MaxRelays string
}

func newTunnelDraft() tunnelDraft { return tunnelDraft{Discovery: true} }

// request is the draft as the agent takes it. The target is read as the CLI
// reads it, a bare port being a port on this machine; the agent checks the
// rest.
func (d tunnelDraft) request() (agent.AgentTunnelRequest, error) {
	target, err := utils.NormalizeLoopbackTarget(d.Target)
	if err != nil || target == "" {
		return agent.AgentTunnelRequest{}, fmt.Errorf("enter a local port, such as 3000, or a host:port")
	}
	maxRelays, err := parseMaxRelays(d.MaxRelays)
	if err != nil {
		return agent.AgentTunnelRequest{}, err
	}
	discovery := d.Discovery
	return agent.AgentTunnelRequest{
		Name:            strings.TrimSpace(d.Name),
		TargetAddr:      target,
		RelayURLs:       utils.SplitCSV(d.Relays),
		Discovery:       &discovery,
		MaxActiveRelays: maxRelays,
	}, nil
}

// settingsDraft is the form of the settings a tunnel keeps while it runs.
type settingsDraft struct {
	MaxRelays   string
	Description string
	Tags        string
	Hide        bool
}

func settingsOf(tunnel agent.AgentTunnelStatus) settingsDraft {
	draft := settingsDraft{
		Description: tunnel.Metadata.Description,
		Tags:        strings.Join(tunnel.Metadata.Tags, ", "),
		Hide:        tunnel.Metadata.Hide,
	}
	if tunnel.MaxActiveRelays > 0 {
		draft.MaxRelays = strconv.Itoa(tunnel.MaxActiveRelays)
	}
	return draft
}

// request changes the fields the form shows and leaves the others, such as
// the owner and the thumbnail, as the agent has them.
func (d settingsDraft) request() (agent.AgentTunnelUpdateRequest, error) {
	maxRelays, err := parseMaxRelays(d.MaxRelays)
	if err != nil {
		return agent.AgentTunnelUpdateRequest{}, err
	}
	description := strings.TrimSpace(d.Description)
	// An empty list, not nil: the agent reads a missing list as "keep the
	// tags", so clearing the field must send [] to clear them.
	tags := utils.SplitCSV(d.Tags)
	if tags == nil {
		tags = []string{}
	}
	hide := d.Hide
	req := agent.AgentTunnelUpdateRequest{Metadata: &agent.AgentMetadataRequest{Description: &description, Tags: &tags, Hide: &hide}}
	if maxRelays > 0 {
		req.MaxActiveRelays = &maxRelays
	}
	return req, nil
}

// parseMaxRelays reads a relay count; empty leaves the agent's default.
func parseMaxRelays(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("max relays must be a positive number")
	}
	return n, nil
}
