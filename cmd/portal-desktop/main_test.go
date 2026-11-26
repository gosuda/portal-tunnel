package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ironpark/ggui"
	gguiruntime "github.com/ironpark/ggui/runtime"

	"github.com/gosuda/portal-tunnel/v2/cmd/portal-tunnel/agent"
	"github.com/gosuda/portal-tunnel/v2/sdk"
)

const probeWidth = 920

func newProbe(t *testing.T, m *model) *ggui.Probe {
	t.Helper()
	p := ggui.ProbeBuilder(func() ggui.Widget { return build(m) }, ggui.Sz(probeWidth, 1400))
	t.Cleanup(p.Close)
	return p
}

func sampleStatus() agent.AgentStatusResponse {
	return agent.AgentStatusResponse{Tunnels: []agent.AgentTunnelStatus{
		{
			ID: "web", Name: "web", State: "running", TargetAddr: "127.0.0.1:3000", Discovery: true, MaxActiveRelays: 3,
			Relays: []agent.AgentRelayStatus{
				{RelayURL: "https://relay-one.example.com", PublicURL: "https://web-0x12.relay-one.example.com/", AliasURL: "https://web.relay-one.example.com/", State: sdk.RelayReady},
				{RelayURL: "https://relay-two.example.com", State: sdk.RelayConnecting, Approval: sdk.RelayApprovalPending},
			},
		},
		{
			ID: "game", Name: "game", State: "running", TargetAddr: "127.0.0.1:25565",
			Relays: []agent.AgentRelayStatus{{RelayURL: "https://relay-one.example.com", PublicURL: "https://game.relay-one.example.com/", TCPAddr: "relay-one.example.com:40001", State: sdk.RelayReady}},
		},
	}}
}

func hasText(p *ggui.Probe, text string) bool {
	_, ok := p.Semantics().Find(ggui.RoleText, text)
	return ok
}

// An HTTP endpoint is a link to copy or open; a TCP one is an address to
// copy, never handed to a browser. A TCP tunnel shows its address next to
// the URL that the relay also reports for it.
func TestDesktopShowsEndpointsByTransport(t *testing.T) {
	t.Parallel()
	m := newModel(t.TempDir(), "", "")
	p := newProbe(t, m)
	m.apply(p, sampleStatus(), nil)

	for _, label := range []string{"Copy https://web.relay-one.example.com/", "Open https://web.relay-one.example.com/", "Copy relay-one.example.com:40001", "Copy https://game.relay-one.example.com/"} {
		if _, ok := p.Find(label); !ok {
			t.Fatalf("%q is missing", label)
		}
	}
	if _, ok := p.Find("Open relay-one.example.com:40001"); ok {
		t.Fatal("a TCP address must not be offered to the browser")
	}
	p.Tap("Copy https://web.relay-one.example.com/")
	if got := p.Clipboard().Read(); got != "https://web.relay-one.example.com/" {
		t.Fatalf("clipboard = %q, want the alias URL", got)
	}
	if !hasText(p, "Waiting for the relay operator to approve this tunnel.") {
		t.Fatal("a relay waiting for approval must say so")
	}
	if _, ok := p.Find("Copy https://relay-two.example.com"); ok {
		t.Fatal("a relay that carries nothing has no endpoint to copy")
	}
}

func TestDesktopShowsTunnelAndRelayErrors(t *testing.T) {
	t.Parallel()
	m := newModel(t.TempDir(), "", "")
	p := newProbe(t, m)
	m.apply(p, agent.AgentStatusResponse{Tunnels: []agent.AgentTunnelStatus{{
		ID: "web", State: "error", LastError: "dial tcp 127.0.0.1:3000: connection refused",
		Relays: []agent.AgentRelayStatus{{RelayURL: "https://relay.example.com", State: sdk.RelayFailed, Failure: sdk.RelayFailureMITM, CertificateError: "issuance refused"}},
	}}}, nil)

	for _, text := range []string{"Tunnel error: dial tcp 127.0.0.1:3000: connection refused", "Relay failure: mitm", "Certificate: issuance refused"} {
		if !hasText(p, text) {
			t.Fatalf("diagnostic %q is hidden", text)
		}
	}
}

// A relay that was disconnected stays on the card with Connect, so that the
// user can undo the disconnect.
func TestDesktopOffersConnectForADisconnectedRelay(t *testing.T) {
	t.Parallel()
	m := newModel(t.TempDir(), "", "")
	p := newProbe(t, m)
	m.apply(p, agent.AgentStatusResponse{Tunnels: []agent.AgentTunnelStatus{{
		ID: "web", State: "running",
		Relays: []agent.AgentRelayStatus{{RelayURL: "https://relay.example.com", State: agent.RelayDisconnected}},
	}}}, nil)

	if _, ok := p.Find("Connect https://relay.example.com"); !ok {
		t.Fatal("a disconnected relay offers no Connect")
	}
	if _, ok := p.Find("Disconnect https://relay.example.com"); ok {
		t.Fatal("a disconnected relay offers Disconnect")
	}
}

// At the smallest window size, the forms scroll above their actions, so the
// actions stay in the window even with an error under the form.
func TestDesktopFormsKeepTheirActionsInTheSmallestWindow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := newModel(dir, filepath.Join(dir, "agent", "config.toml"), filepath.Join(dir, "portal"))
	p := ggui.ProbeBuilder(func() ggui.Widget { return build(m) }, ggui.Sz(minWidth, minHeight))
	t.Cleanup(p.Close)
	m.apply(p, sampleStatus(), nil)
	inWindow := func(form, label string) {
		t.Helper()
		m.FormError.Set(strings.Repeat("the agent refused the request. ", 10))
		p.Advance(time.Second)
		button, ok := p.Find(label)
		if r := button.Rect; !ok || r.Size.H <= 0 || r.Origin.Y+r.Size.H > minHeight || r.Origin.X+r.Size.W > minWidth {
			t.Fatalf("%s: %q is outside the window at %v", form, label, button.Rect)
		}
	}

	p.Tap("Expose a service")
	p.Advance(time.Second)
	inWindow("expose", "Expose")
	inWindow("expose", "Cancel")
	p.Tap("Cancel")
	p.Advance(time.Second)

	p.Tap("Settings for web")
	p.Advance(time.Second)
	inWindow("settings", "Save")
	p.Tap("Cancel")
	p.Advance(time.Second)

	m.apply(p, agent.AgentStatusResponse{}, agent.ErrNotRunning)
	p.Tap("Set up and start")
	p.Advance(time.Second)
	inWindow("setup", "Install and start")
}

func notificationIDs(p *ggui.Probe) []string {
	var ids []string
	for _, n := range p.Notifications() {
		ids = append(ids, n.ID)
	}
	slices.Sort(ids)
	return ids
}

// The first answer is the baseline; later changes worth attention, and the
// agent going away, are notified, and a recovery withdraws the outage.
func TestDesktopNotifiesStateChanges(t *testing.T) {
	t.Parallel()
	m := newModel(t.TempDir(), "", "")
	p := newProbe(t, m)
	quiet := agent.AgentStatusResponse{Tunnels: []agent.AgentTunnelStatus{{
		ID: "web", State: "running",
		Relays: []agent.AgentRelayStatus{{RelayURL: "https://relay.example.com", State: sdk.RelayReady}},
	}}}
	m.apply(p, quiet, nil)
	m.apply(p, quiet, nil)
	if ids := notificationIDs(p); len(ids) != 0 {
		t.Fatalf("notifications without a change: %v", ids)
	}

	failing := agent.AgentStatusResponse{Tunnels: []agent.AgentTunnelStatus{{
		ID: "web", State: "error", LastError: "boom",
		Relays: []agent.AgentRelayStatus{{RelayURL: "https://relay.example.com", State: sdk.RelayConnecting, Approval: sdk.RelayApprovalPending}},
	}}}
	m.apply(p, failing, nil)
	want := []string{"relay/web/https://relay.example.com", "tunnel/web"}
	if ids := notificationIDs(p); !slices.Equal(ids, want) {
		t.Fatalf("notifications = %v, want %v", ids, want)
	}

	m.apply(p, agent.AgentStatusResponse{}, agent.ErrNotRunning)
	if ids := notificationIDs(p); !slices.Contains(ids, "agent") {
		t.Fatalf("losing the agent was not notified: %v", ids)
	}
	m.apply(p, quiet, nil)
	if ids := notificationIDs(p); slices.Contains(ids, "agent") {
		t.Fatalf("the outage notification outlived the agent's return: %v", ids)
	}
}

// Losing the agent keeps the last list and the user's draft, holds back
// requests, and says how to start the agent again.
func TestDesktopKeepsContextWhileTheAgentIsAway(t *testing.T) {
	t.Parallel()
	m := newModel(t.TempDir(), "", "")
	p := newProbe(t, m)
	m.apply(p, sampleStatus(), nil)
	p.Tap("Expose a service")
	p.Advance(time.Second)
	draft := tunnelDraft{Name: "docs", Target: "8080", Discovery: true}
	m.Draft.Set(draft)

	m.apply(p, agent.AgentStatusResponse{}, agent.ErrNotRunning)
	if !ggui.Peek(m.Adding) || ggui.Peek(m.Draft) != draft {
		t.Fatal("the add form or its draft was lost while the agent was away")
	}
	if !hasText(p, startCommand) {
		t.Fatal("the window does not say how to start the agent")
	}
	if _, ok := p.Find("Expose"); ok {
		t.Fatal("Expose must be disabled while the agent is away")
	}
	p.Tap("Cancel")
	p.Advance(time.Second)
	if !hasText(p, "Forwards to 127.0.0.1:3000 · discovery on · up to 3 relays") {
		t.Fatal("the last known tunnels were dropped")
	}
	if _, ok := p.Find("Delete web"); ok {
		t.Fatal("Delete must wait for the agent")
	}
	p.Tap("Copy command")
	if got := p.Clipboard().Read(); got != startCommand {
		t.Fatalf("clipboard = %q, want %q", got, startCommand)
	}
}

// Setting up the agent creates its config and installs it as a service only
// after the user agrees, and keeps the sheet open with the reason when
// portal agent run fails.
func TestDesktopAsksBeforeItSetsUpTheAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent", "config.toml")
	m := newModel(dir, configPath, filepath.Join(dir, "missing", "portal"))
	p := newProbe(t, m)
	m.apply(p, agent.AgentStatusResponse{}, agent.ErrNotRunning)

	p.Tap("Set up and start")
	p.Advance(time.Second)
	p.Tap("Cancel")
	p.Advance(time.Second)
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("the config was created without consent: %v", err)
	}

	p.Tap("Set up and start")
	p.Advance(time.Second)
	p.Tap("Install and start")
	waitFor(t, p, "the failure of portal agent run", func() bool { return ggui.Peek(m.FormError) != "" })
	if _, err := agent.LoadExistingConfig(configPath); err != nil {
		t.Fatalf("the agreed config was not created: %v", err)
	}
	if !ggui.Peek(m.SettingUp) {
		t.Fatal("the setup sheet closed though the agent did not start")
	}

	without := newModel(dir, configPath, "")
	q := newProbe(t, without)
	without.apply(q, agent.AgentStatusResponse{}, agent.ErrNotRunning)
	if _, ok := q.Find("Set up and start"); ok {
		t.Fatal("setup was offered without a portal CLI to run")
	}
}

func TestTunnelDraftRequest(t *testing.T) {
	t.Parallel()
	req, err := tunnelDraft{Name: " web ", Target: "3000", Relays: "relay-one.example.com, https://relay-two.example.com", Discovery: false, MaxRelays: "2"}.request()
	if err != nil {
		t.Fatal(err)
	}
	if req.Name != "web" || req.TargetAddr != "127.0.0.1:3000" || req.Discovery == nil || *req.Discovery || req.MaxActiveRelays != 2 ||
		!slices.Equal(req.RelayURLs, []string{"relay-one.example.com", "https://relay-two.example.com"}) {
		t.Fatalf("request = %+v", req)
	}
	for _, draft := range []tunnelDraft{{Name: "web"}, {Name: "web", Target: "3000", MaxRelays: "0"}, {Name: "web", Target: "3000", MaxRelays: "many"}} {
		if _, err := draft.request(); err == nil {
			t.Fatalf("draft %+v was accepted", draft)
		}
	}
}

// Clearing the tags field clears the tags: the agent keeps the tags of a
// request without a list, so the request must carry an empty one.
func TestSettingsDraftClearsTags(t *testing.T) {
	t.Parallel()
	req, err := settingsDraft{Tags: " , "}.request()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var got agent.AgentTunnelUpdateRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Metadata == nil || got.Metadata.Tags == nil || len(*got.Metadata.Tags) != 0 {
		t.Fatalf("request %s does not clear the tags", body)
	}
}

// A save sends the relay count only when the user changed it, so that it
// does not write the agent's default into the config, and refuses an
// emptied count, which the agent cannot take back to its default.
func TestSettingsDraftSendsOnlyAChangedRelayCount(t *testing.T) {
	t.Parallel()
	opened := settingsOf(agent.AgentTunnelStatus{MaxActiveRelays: 3})
	req, err := opened.request()
	if err != nil || req.MaxActiveRelays != nil {
		t.Fatalf("unchanged count: request = %+v, err = %v", req, err)
	}
	changed := opened
	changed.MaxRelays = " 5 "
	if req, err := changed.request(); err != nil || req.MaxActiveRelays == nil || *req.MaxActiveRelays != 5 {
		t.Fatalf("changed count: request = %+v, err = %v", req, err)
	}
	cleared := opened
	cleared.MaxRelays = ""
	if _, err := cleared.request(); err == nil {
		t.Fatal("an emptied relay count was accepted")
	}
}

// A later launch that names another agent is reported, so that it is not
// dropped without a word; one that names nothing or this window's agent is
// not.
func TestOtherAgentOfALaterLaunch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "a.toml")
	stateDir := filepath.Join(dir, "state")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{},
		{args: []string{"--hidden"}},
		{args: []string{"--config", "a.toml"}},
		{args: []string{"--config", configPath}},
		{args: []string{"--config", "b.toml"}, want: filepath.Join(dir, "b.toml")},
		{args: []string{"--state-dir", filepath.Join(dir, "other")}, want: filepath.Join(dir, "other")},
		{args: []string{"--unknown"}},
	} {
		if got := otherAgent(gguiruntime.Launch{Args: tc.args, Dir: dir}, configPath, stateDir); got != tc.want {
			t.Errorf("otherAgent(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// The window wears Portal's colors and radius: theme.css holds the
// declarations of the frontend's stylesheet, which stays their source.
func TestThemeMatchesTheFrontend(t *testing.T) {
	t.Parallel()
	frontend, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "index.css"))
	if err != nil {
		t.Fatal(err)
	}
	for decl := range strings.SplitSeq(themeCSS, ";") {
		_, decl, _ = strings.Cut(decl, "--")
		if decl = strings.TrimSpace(decl); decl != "" && !strings.Contains(string(frontend), "--"+decl+";") {
			t.Errorf("theme.css declares --%s, which frontend/src/index.css does not", decl)
		}
	}
}

// startAgent runs a real agent with no tunnels, as `portal agent run
// --foreground` would, and returns its state directory.
func startAgent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	config := fmt.Sprintf("[agent]\nstate_dir = '%s'\ncontrol_addr = '127.0.0.1:0'\n", dir)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := agent.LoadExistingConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return dir
}

// waitFor runs frames until cond holds: the agent's answers land in frames.
func waitFor(t *testing.T, p *ggui.Probe, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
		p.Frame()
	}
}

// The desktop adds and deletes a tunnel through a real agent's Control API,
// and closing it leaves the agent running.
func TestDesktopManagesTunnelsThroughTheAgent(t *testing.T) {
	stateDir := startAgent(t)
	m := newModel(stateDir, "", "")
	p := ggui.ProbeBuilder(func() ggui.Widget { return build(m) }, ggui.Sz(probeWidth, 1400))
	p.Setup(func() { m.start(p) })
	waitFor(t, p, "the agent", func() bool { return ggui.Peek(m.Connection) == connected })

	p.Tap("Expose a service")
	p.Advance(time.Second)
	m.Draft.Set(tunnelDraft{Name: "web", Target: "127.0.0.1:1", Relays: "https://127.0.0.1:9", Discovery: false})
	p.Tap("Expose")
	waitFor(t, p, "the new tunnel", func() bool {
		_, ok := findTunnel(ggui.Peek(m.Status), "web")
		return ok && !ggui.Peek(m.Adding)
	})
	p.Advance(time.Second)
	if msg := ggui.Peek(m.FormError); msg != "" {
		t.Fatalf("form error %q", msg)
	}

	p.Tap("Expose a service")
	p.Advance(time.Second)
	m.Draft.Set(tunnelDraft{Name: "web", Target: "3000"})
	p.Tap("Expose")
	waitFor(t, p, "the refusal of a duplicate", func() bool { return ggui.Peek(m.FormError) != "" })
	p.Tap("Cancel")
	p.Advance(time.Second)

	p.Tap("Delete web")
	p.Advance(time.Second)
	p.Tap("Delete")
	waitFor(t, p, "the deletion", func() bool { return len(ggui.Peek(m.Status).Tunnels) == 0 })

	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := agent.Status(ctx, stateDir); err != nil {
		t.Fatalf("the agent stopped with the desktop: %v", err)
	}
}
