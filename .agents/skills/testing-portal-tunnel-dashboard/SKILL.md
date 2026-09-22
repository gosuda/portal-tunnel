---
name: testing-portal-tunnel-dashboard
description: How to drive the portal-tunnel agent dashboard bubbletea TUI end-to-end without a live agent or relay, using a stub control server plus a fabricated agent-endpoint.json.
---

# Testing the portal-tunnel agent dashboard TUI standalone

The `portal-tunnel agent dashboard` TUI looks like it needs a running agent, but it only needs two things: a state dir containing `agent-endpoint.json`, and an HTTP server at the endpoint's `control_addr` that speaks the control API envelope.

## How the dashboard gets its data

- `portal-tunnel agent dashboard --state-dir DIR` reads `DIR/agent-endpoint.json` (`cmd/portal-tunnel/agent/control.go`, `endpointFilename = "agent-endpoint.json"`).
- The file is `{"control_addr":"HOST:PORT","token":"TOKEN"}`.
- Every poll tick it issues `GET http://<control_addr>/agent/status` with `Authorization: Bearer <token>` (`types.PathAgentStatus`).
- Responses must use the repo's API envelope: `{"ok": true, "data": <AgentStatusResponse>}`. Returning the raw status object without the envelope yields "Agent unavailable: api response is not ok" in the TUI.
- `AgentStatusResponse` / `AgentTunnelStatus` shapes live in `cmd/portal-tunnel/agent/api_types.go` (`tunnels[].metadata` is `types.LeaseMetadata`).

## Recipe

1. `go build -o /tmp/portal-tunnel ./cmd/portal-tunnel`
2. Write a stub HTTP server that answers `GET /agent/status` with `{"ok":true,"data":{...}}` containing a fabricated tunnel (id, name, state "running", target_addr, max_active_relays, metadata, relays[]). Other paths can return an error — the TUI only shows them if you trigger an action.
3. `mkdir -p /tmp/dash-state && printf '{"control_addr":"127.0.0.1:PORT","token":"tk"}' > /tmp/dash-state/agent-endpoint.json`
4. Launch on the KDE desktop: `DISPLAY=:0 konsole -e /tmp/portal-tunnel agent dashboard --state-dir /tmp/dash-state`, then `wmctrl -r "portal-tunnel" -b add,maximized_vert,maximized_horz` (height matters — settings/add-tunnel rows are clipped to pane height).
5. The TUI self-populates on the next poll tick — no restart needed when the stub comes up.

## Driving the TUI

- Mouse clicks work (`tea.WithMouseCellMotion`): clickable regions include section titles, buttons, tunnel/relay rows, and full-width input rows. Clicking an input row focuses that field via `agentDashboardActionFocus{Settings,AddTunnel}Field`.
- Keys: left/right cycle panes; tab/down & shift+tab/up cycle fields within add-tunnel and settings panes; `esc` cancels add-tunnel input; `ctrl+c` quits.
- "Add Tunnel" button toggles the form locally (`m.addingTunnel`) — the 11-row form renders without any backend round-trip.
- Settings input rows only render when `status.tunnels` is non-empty and a tunnel is selected — the fabricated status must contain at least one tunnel.

## Verifying provider input validation without credentials

The six `portal/acme/*` providers (`cloudflare`, `gcloud`, `hetzner`, `njalla`, `route53`, `vultr`) validate method inputs in `internal/dnsrecord` before hitting the network, and all have exported constructors. A throwaway Go module with `replace github.com/gosuda/portal-tunnel/v2 => <repo>` can call e.g. `p.EnsureARecord(ctx, "", "1.2.3.4")` and assert exact error strings ("record name is required", `invalid ipv4 address: "..."`, etc.).

Two providers gate before or right after the input checks:

- cloudflare checks `p.token` before validating inputs — construct with any nonempty token (`cloudflare.New("tk")`) or you get `cloudflare token is required` instead of the input error.
- gcloud validates inputs first, then resolves credentials — an invalid input still yields the input error, but the next failure is `load gcloud credentials` on a machine without ambient ADC, or `gcloud project id is required` when credentials resolve but carry no project.

Set `AWS_EC2_METADATA_DISABLED=true` so route53 credential resolution fails fast instead of probing IMDS. Optional stronger check (hits real APIs — skip for offline runs): with a syntactically valid input + fake token, hetzner, njalla, and vultr reach their real HTTP APIs and return 401s — proof inputs traversed the full path.

## Repo conventions worth knowing

- AGENTS.md: run tests only when explicitly requested; CI commands are `make vet`, `make lint`, `make test`.
- `make lint` needs golangci-lint + gojgp; both install via `make install` into `~/go/bin` (add `/usr/local/go/bin` and `~/go/bin` to PATH).
- Scoped testing preferred: `go test -v -count=1 ./portal/acme/internal/dnsrecord/` + `go test -v -count=1 ./sdk/ -run 'TestMITMProbeDialAddress'` rather than the whole suite.

## Devin Secrets Needed

None for the above. Real end-to-end DNS provider testing would need live provider credentials/zones (cloudflare token, AWS keys, hetzner/njalla/vultr tokens, GCP service account) plus a test domain — request only if a future change requires true provider round-trips.
