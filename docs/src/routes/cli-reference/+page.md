---
title: CLI Reference
description: Complete reference for Portal CLI commands, flags, and usage examples.
---

# CLI Reference

The `portal` CLI exposes local services through Portal relay servers. The relay
provides transport and routing. The tunnel process decides whether a connection
is handled as the default HTTPS stream, routed HTTP, raw TCP, or UDP.

## Install

### macOS / Linux

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

### Windows PowerShell

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

### From A Relay

If your relay publishes its own installer:

```bash
curl -sSL https://portal.example.com/install.sh | bash
```

The installer writes the `portal` binary only. It does not write a config file.

## Command Overview

| Command | Purpose |
|---------|---------|
| `portal expose` | Expose one local service or one routed HTTP bundle |
| `portal list` | Print relay URLs resolved for this invocation |
| `portal agent` | Run a durable local multi-tunnel agent |
| `portal update` | Replace the CLI with the latest release |
| `portal version` | Print the current version |

## `portal expose`

Expose a local service:

```bash
portal expose [flags] <target>
```

Or run routed HTTP mode:

```bash
portal expose [flags] --http-route PATH=UPSTREAM [--http-route PATH=UPSTREAM]
```

### Target Formats

| Format | Example | Resolves to |
|--------|---------|-------------|
| Bare port | `3000` | `127.0.0.1:3000` |
| Host and port | `localhost:8080` | `localhost:8080` |
| URL host | `http://127.0.0.1:3000` | `127.0.0.1:3000` |

URL inputs are accepted for address parsing. Paths, queries, and fragments are
not supported.

### Mode Selection

| Mode | Example | Notes |
|------|---------|-------|
| Default HTTPS stream | `portal expose 3000` | Relay routes by SNI; tunnel process terminates tenant TLS |
| Routed HTTP | `portal expose --http-route /api=3001 --http-route /=5173` | Tunnel process runs the HTTP reverse proxy |
| Dedicated raw TCP | `portal expose localhost:25565 --tcp` | Relay allocates a public TCP port |
| UDP relay | `portal expose 8080 --udp --udp-addr 19132` | Relay allocates a public UDP port |

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | registry | Additional relay API URLs, comma-separated |
| `--discovery` | bool | `true` | Include registry relays and relay discovery expansion |
| `--max-active-relays` | int | `3` | Maximum auto-selected relays to keep connected; explicit relays are always included |
| `--multi-hop` | string | | Ordered multi-hop relay API URLs, comma-separated |
| `--multi-hop-depth` | int | `0` | Automatically select one multi-hop route with this hop count; `0` or `1` disables multi-hop |
| `--ban-mitm` | bool | `true` | Ban relay when the MITM self-probe detects TLS termination |
| `--identity-path` | string | `identity.json` | Identity JSON file path; created automatically when missing |
| `--identity-json` | string | | Identity JSON payload; overrides `--identity-path` contents and is persisted there when both are set |
| `--name` | string | auto | Public hostname prefix, one DNS label |
| `--description` | string | | Service description metadata |
| `--tags` | string | | Service tags metadata, comma-separated |
| `--thumbnail` | string | | Service thumbnail URL metadata |
| `--owner` | string | | Service owner metadata |
| `--hide` | bool | `false` | Hide service from relay listing screens |
| `--http-route` | string | | HTTP route mapping in `PATH=UPSTREAM` form; repeatable |
| `--tcp` | bool | `false` | Request a dedicated raw TCP port on the relay |
| `--udp` | bool | `false` | Enable public UDP relay in addition to the default stream path |
| `--udp-addr` | string | | Local UDP target; defaults to the primary target when `--udp` is enabled |
| `--metrics-addr` | string | | Optional `host:port` for Prometheus `/metrics` |

### Constraints

- `<target>` cannot be combined with `--http-route`.
- `--http-route` cannot be combined with `--udp`.
- Explicit `--multi-hop` cannot be combined with automatic `--multi-hop-depth`.
- Multi-hop currently supports only the default SNI TLS stream transport.
- `--tcp` and `--udp` require matching transport support on the relay.

### Examples

Expose a local web app:

```bash
portal expose 3000
```

Use a custom name and relay:

```bash
portal expose localhost:8080 \
  --name myapp \
  --relays https://portal.example.com \
  --discovery=false \
  --description "My web application" \
  --tags webapp,demo
```

Run routed HTTP mode:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Route matching is longest-prefix-first. `/api` matches `/api/*` and strips the
`/api` prefix before proxying to the upstream.

Expose a Minecraft server:

```bash
portal expose localhost:25565 --name minecraft --tcp
```

Enable UDP alongside the default stream target:

```bash
portal expose localhost:8080 --udp --udp-addr localhost:19132 --name game
```

Use an explicit multi-hop route:

```bash
portal expose 3000 --multi-hop https://entry.example.com,https://exit.example.com
```

Ask Portal to select one three-hop route:

```bash
portal expose 3000 --multi-hop-depth 3
```

Keep MITM probe failures warning-only:

```bash
portal expose 3000 --ban-mitm=false
```

## `portal list`

Print relay URLs resolved for the current invocation:

```bash
portal list [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | registry | Additional relay URLs |
| `--default-relays` | bool | `true` | Include public registry relays |

`portal list` does not run the runtime relay discovery expansion loop. It only
resolves the registry seed list plus explicit relay URLs.

## `portal agent`

Run a durable local agent that owns multiple tunnels from one config file:

```bash
portal agent run
portal agent dashboard
portal agent stop
portal agent restart
```

| Command | Description |
|---------|-------------|
| `portal agent run` | Install or update and start the managed agent service |
| `portal agent run --config config.toml --foreground` | Run the agent in the current terminal |
| `portal agent dashboard` | Open the local TUI for tunnels, relays, and multi-hop routes |
| `portal agent stop` | Gracefully stop the agent and disable or stop the OS service |
| `portal agent restart` | Stop the current agent if present, install or update the service, and start it again |

The local control API binds only to loopback and uses a token in the agent state
directory. See [Configuration Reference](/configuration#configtoml) for the
`config.toml` format.

## `portal update`

Update the CLI binary:

```bash
portal update
```

The updater resolves the latest GitHub release, compares it with the installed
version, downloads the matching asset, verifies its SHA256 checksum, and
replaces the current executable.

## `portal version`

```bash
portal version
```

Prints the installed version string and exits.

## Behavior Notes

- `portal expose` and `portal list` check for new releases in the background.
- `portal expose` loads or creates a signing identity at `identity.json` or
  `--identity-path`.
- Multiple relay URLs are registered independently. A failed relay does not stop
  healthy relays from serving.
- With discovery enabled, the tunnel consumes relay `/discovery` results and
  reconciles its relay pool.
- MITM enforcement is enabled by default for the default stream path.
- When the local stream target is unreachable, the tunnel returns an HTTP 503
  page to browser-style clients.
- Routed HTTP mode is HTTP-only and runs inside the tunnel process.
- `--tcp` requires relay TCP port transport, a valid `MIN_PORT`/`MAX_PORT`
  range, and TCP port transport enabled in the admin panel.
- `--udp` requires relay UDP transport, a valid `MIN_PORT`/`MAX_PORT` range, UDP
  enabled in the admin panel, and `SNI_PORT/udp` reachable for the QUIC backhaul.
- Bare `portal [flags]` is not accepted; use `portal expose` explicitly.
- Runtime `APP_*`, `RELAYS`, and `DEFAULT_RELAYS` environment variable fallbacks
  are not used.

## Next Steps

- [Getting Started](/getting-started): run your first tunnel
- [Concepts](/concepts): understand the relay and transport model
- [TCP and UDP Tunneling](/tcp-udp-tunneling): raw TCP and UDP setup
- [Deployment](/deployment): run your own relay server
