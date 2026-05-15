---
title: Portal Agent
description: Run durable multi-tunnel Portal services from a local config file.
---

# Portal Agent

`portal agent` is the long-lived version of `portal expose`. It runs one local
agent process, reads a TOML config file, and keeps every declared tunnel
registered with the selected relays.

Use the agent when tunnels should survive terminal closes, login sessions, or
manual restarts. Use `portal expose` for one-off development sessions.

## What The Agent Owns

The agent owns:

- one `config.toml`
- one local loopback control API
- one OS service when run in managed mode
- one or more tunnel runtimes declared under `[[tunnels]]`
- tunnel identities stored under the agent state directory unless overridden

Each tunnel still uses the normal Portal SDK path internally: it registers a
lease, opens reverse sessions, renews the lease, and proxies traffic to the
configured local target.

## Create A Config

`portal agent run` requires an existing config file. The installer does not
create one.

Default config paths:

| OS | Config path |
|----|-------------|
| Linux user | `$XDG_CONFIG_HOME/portal-tunnel/agent/config.toml` or `~/.config/portal-tunnel/agent/config.toml` |
| Linux root | `/etc/portal-tunnel/agent/config.toml` |
| macOS user | `~/Library/Application Support/Portal Tunnel/Agent/config.toml` |
| macOS root | `/Library/Application Support/Portal Tunnel/Agent/config.toml` |
| Windows | `%ProgramData%\Portal Tunnel\Agent\config.toml` |

Minimal config:

```toml
[agent]
control_addr = "127.0.0.1:4018"
service_name = "portal-agent"

[[tunnels]]
id = "web"
name = "myapp"
target = "127.0.0.1:3000"
relays = ["https://portal.example.com"]
discovery = false
description = "Managed web tunnel"
tags = ["web"]
```

Routed HTTP config:

```toml
[agent]
control_addr = "127.0.0.1:4018"
service_name = "portal-agent"

[[tunnels]]
id = "frontend"
name = "myapp"
relays = ["https://portal.example.com"]
discovery = false

[[tunnels.http_routes]]
prefix = "/api"
upstream = "http://127.0.0.1:3001"

[[tunnels.http_routes]]
prefix = "/"
upstream = "http://127.0.0.1:5173"
```

Relative paths in the config are resolved from the config file directory.

## Run The Agent

Run as a managed OS service:

```bash
portal agent run
```

Run in the current terminal:

```bash
portal agent run --config config.toml --foreground
```

Open the local dashboard:

```bash
portal agent dashboard
```

Restart or stop:

```bash
portal agent restart
portal agent stop
```

`portal agent run`, `stop`, and `restart` load the config so they can find the
state directory and service name. `portal agent dashboard` can attach with only
the default state directory or an explicit `--state-dir`.

`portal agent run --service` is the internal service entrypoint installed by
`portal agent run`. Operators normally do not run it directly.

## Dashboard

The dashboard is a local terminal UI. It polls agent status every two seconds
and edits the same TOML config file that the service uses.

Dashboard panes:

| Pane | Purpose |
|------|---------|
| Tunnels | Add, select, and delete simple target tunnels |
| Settings | Edit max active relays and public metadata |
| Relays | Connect or disconnect relays for the selected tunnel |
| Multi-hop | Build and apply an ordered multi-hop route |

Keyboard controls:

| Key | Action |
|-----|--------|
| `left` / `right` | Switch panes |
| `up` / `down` | Move within the active pane |
| `enter` | Apply the active action |
| `delete` | Delete the selected tunnel or disconnect the selected relay |
| `c` | Connect the selected relay in the Relays pane |
| `d` | Disconnect the selected relay in the Relays pane |
| `o` | Open the selected public tunnel URL |
| `a` | Add the selected relay as a multi-hop hop |
| `p` | Apply a drafted multi-hop route |
| `esc` | Cancel input or return to the Tunnels pane |
| `ctrl+c` | Exit the dashboard |

The Add Tunnel action accepts `name port`, for example `myapp 3000`. It creates
a simple loopback target tunnel. Advanced options such as `http_routes`, UDP,
TCP, custom identity JSON, or explicit multi-hop defaults should be edited in
`config.toml`.

## Tunnel Config Fields

Common fields:

| Field | Description |
|-------|-------------|
| `id` | Stable local tunnel ID used by the dashboard and control API |
| `name` | Public lease name, used as the subdomain label |
| `target` | Local TCP target, equivalent to `portal expose <target>` |
| `http_routes` | Routed HTTP mappings; cannot be combined with `target` or `udp` |
| `relays` | Explicit relay API URLs |
| `discovery` | Include registry and relay discovery expansion |
| `max_active_relays` | Maximum auto-selected relays kept connected |
| `identity_path` | Tunnel identity JSON path |
| `identity_json` | Identity JSON payload; persisted to `identity_path` when both are set |
| `udp`, `udp_addr` | UDP transport settings |
| `tcp` | Dedicated raw TCP port setting |
| `multi_hop` | Explicit ordered multi-hop relay URLs |
| `multi_hop_depth` | Automatically choose one multi-hop route with this depth |
| `ban_mitm` | Ban relays when the TLS self-probe detects termination |
| `description`, `tags`, `owner`, `thumbnail`, `hide` | Public relay metadata |

Constraints match `portal expose`:

- `target` cannot be combined with `http_routes`.
- `http_routes` cannot be combined with `udp`.
- `multi_hop` requires at least two relay URLs.
- `multi_hop` cannot be combined with `multi_hop_depth`.
- Multi-hop currently supports only the default stream transport, not UDP or raw
  TCP port mode.

## Identity Layout

If `identity_path` is omitted:

- a single tunnel uses `<state_dir>/identity.json`
- multiple tunnels use `<state_dir>/<tunnel-id>/identity.json`

Reusing an identity keeps the same tunnel address and lease identity across
restarts. Use separate identity paths when two tunnels should have separate
lease identities.

## Local Control API

The agent writes this file while running:

```text
<state_dir>/agent-endpoint.json
```

It contains the loopback control address and a random bearer token. CLI commands
read this file and send `Authorization: Bearer <token>` to the local control
API.

The agent refuses non-loopback `control_addr` values. Use `127.0.0.1`,
`localhost`, or another loopback address.

Control endpoints:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/v1/agent/status` | Bearer token or wallet session | Read agent and tunnel status |
| `POST` | `/v1/agent/shutdown` | Bearer token | Ask the agent to stop |
| `POST` | `/v1/agent/tunnels` | Bearer token | Add a simple target tunnel |
| `PATCH` | `/v1/agent/tunnels/{id}` | Bearer token | Update metadata or max active relays |
| `DELETE` | `/v1/agent/tunnels/{id}` | Bearer token | Delete a tunnel |
| `POST` | `/v1/agent/tunnels/{id}/relays` | Bearer token | Connect a relay |
| `DELETE` | `/v1/agent/tunnels/{id}/relays` | Bearer token | Disconnect a relay |
| `POST` | `/v1/agent/tunnels/{id}/multi-hop` | Bearer token | Apply a multi-hop route |
| `DELETE` | `/v1/agent/tunnels/{id}/multi-hop` | Bearer token | Clear multi-hop routing |

Wallet auth endpoints also exist under `/v1/agent/auth/*`. Wallet-authenticated
requests are read-only and can only call `/v1/agent/status`; mutating operations
use the local bearer token from the state directory.

## Agent Wallet Access

Set `agent.allowed_wallets` to restrict wallet-authenticated status access:

```toml
[agent]
allowed_wallets = ["0x1234567890abcdef1234567890abcdef12345678"]
```

When `allowed_wallets` is empty, any wallet can sign in to the loopback agent
auth endpoint. This does not grant mutation rights; the bearer token still owns
config and tunnel changes.

## Troubleshooting

If the dashboard says the agent is unavailable, start it explicitly:

```bash
portal agent run --config config.toml
```

If the OS service manager is unavailable:

```bash
portal agent run --config config.toml --foreground
```

If a tunnel is stuck in `error`, check the selected tunnel row in the dashboard.
Common causes are an invalid local target, a relay URL that cannot be reached, a
transport disabled on the relay, or an invalid multi-hop route.

## Next Steps

- [Configuration Reference](/configuration#configtoml): every agent config field
- [Wallet and ENS](/wallet-and-ens): wallet auth and ENS gasless behavior
- [CLI Reference](/cli-reference): command flags and examples
