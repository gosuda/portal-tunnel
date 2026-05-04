---
title: CLI Reference
description: Complete reference for the Portal CLI commands, flags, and usage examples.
---

# CLI Reference

The `portal` CLI exposes local services through Portal relay servers. This page documents all commands, flags, and usage patterns.

## Installation

### macOS / Linux

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

### Windows (PowerShell)

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

### From a relay

If your relay publishes its own installer:

```bash
curl -sSL https://portal.example.com/install.sh | bash
```

The installer downloads the `portal` binary and adds it to your PATH. No configuration file is written. Already installed? Run `portal update` to get the latest version.

## Commands

### `portal expose`

Expose a local service to the internet.

```bash
portal expose [flags] <target>
```

**Target formats:**

| Format | Example | Resolves to |
|--------|---------|-------------|
| Bare port | `3000` | `127.0.0.1:3000` |
| Host:port | `localhost:8080` | `localhost:8080` |
| URL | `http://127.0.0.1:3000` | `127.0.0.1:3000` |

Instead of a positional target, you can use `--http-route` for multi-service routing.

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | _(registry)_ | Portal relay API URLs (comma-separated, https only) |
| `--discovery` | bool | `true` | Include public registry relays and discover additional bootstraps |
| `--multi-hop` | string | | Ordered multi-hop relay API URLs, comma-separated |
| `--multi-hop-depth` | int | `0` | Automatically select one multi-hop route with this hop count; 0 or 1 disables multi-hop |
| `--max-active-relays` | int | `3` | Maximum auto-selected relays to keep connected; explicit relays are always included |
| `--ban-mitm` | bool | `true` | Ban relay when the MITM self-probe detects TLS termination |
| `--identity-path` | string | `./identity.json` | Identity JSON file path; created automatically when missing |
| `--identity-json` | string | | Identity JSON payload; overrides `--identity-path` contents and is persisted there when both are set |
| `--name` | string | _(auto)_ | Public hostname prefix (single DNS label); auto-generated when omitted |
| `--description` | string | | Service description metadata |
| `--tags` | string | | Service tags metadata (comma-separated) |
| `--thumbnail` | string | | Service thumbnail URL metadata |
| `--owner` | string | | Service owner metadata |
| `--hide` | bool | `false` | Hide service from relay listing screens |
| `--tcp` | bool | `false` | Request a dedicated TCP port for raw TCP services (no TLS) |
| `--udp` | bool | `false` | Enable public UDP relay in addition to the default stream path |
| `--udp-addr` | string | | Local UDP target address; defaults to the primary target when `--udp` is enabled |
| `--http-route` | string | | HTTP route mapping in `PATH=UPSTREAM` form; repeat for multiple routes |

**Examples:**

Basic usage:

```bash
portal expose 3000
```

With custom name and relay:

```bash
portal expose localhost:8080 \
  --name myapp \
  --relays https://portal.example.com \
  --description "My web application" \
  --tags webapp,demo
```

TCP port routing (Minecraft server):

```bash
portal expose localhost:25565 --name minecraft --tcp
```

Multi-service HTTP routing:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Route matching is longest-prefix-first. `/api` matches `/api/*` and strips the `/api` prefix before proxying to the upstream. Routed HTTP mode automatically forwards `X-Forwarded-*` headers, rewrites upstream `Location` redirects, and remaps cookie paths.

Disable relay discovery:

```bash
portal expose 3000 --relays https://portal.example.com --discovery=false
```

Explicit multi-hop route:

```bash
portal expose 3000 --multi-hop https://entry.example.com,https://transit.example.com,https://exit.example.com
```

Automatic multi-hop route:

```bash
portal expose 3000 --multi-hop-depth 3
```

Warning-only MITM mode:

```bash
portal expose 3000 --ban-mitm=false
```

### `portal list`

Print the relay URLs that the CLI will use.

```bash
portal list [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--relays` | string | _(registry)_ | Additional relay URLs |
| `--default-relays` | bool | `true` | Include public registry relays |

Unlike `portal expose`, `portal list` does not run the relay discovery expansion loop. It only resolves the registry seed list plus explicit `--relays` values.

### `portal agent`

Run a durable local agent that owns multiple tunnels from one config file.

```bash
portal agent run
portal agent dashboard
portal agent stop
```

`portal agent run` reads or creates the platform default `config.toml`, installs or updates the OS-managed service, starts it, and opens the dashboard when invoked from an interactive terminal. Use `--foreground` for local debugging without service registration.
Use `portal agent dashboard` to attach to an already running local agent. When using `--foreground`, keep that process running in one terminal and open the dashboard from another.

**Subcommands:**

| Command | Description |
|---------|-------------|
| `portal agent run` | Install/update and start the managed agent service |
| `portal agent run --config config.toml --foreground` | Run the agent in the current terminal |
| `portal agent dashboard` | Open the mouse-capable local TUI for tunnels, relay attach/detach, relay lists, and multi-hop route changes |
| `portal agent stop` | Gracefully stop the agent and disable/stop the OS service |

The local control API binds only to loopback and uses a token in the agent state directory. See [Configuration Reference](/configuration#configtoml) for the `config.toml` format.

### `portal update`

Update the CLI binary to the latest release.

```bash
portal update
```

The update flow:

1. Checks the latest version by resolving the GitHub releases redirect URL
2. Compares with the currently installed version
3. If a newer version exists: downloads the binary, verifies its SHA256 checksum, and replaces the current executable
4. If already up to date: prints a message and exits

No flags. Works on macOS, Linux, and Windows. Requires write access to the directory containing the `portal` binary.

**Examples:**

```bash
# Update to the latest version
portal update
# Already up to date (v2.1.5).

# Or when a new version is available:
portal update
# Updating v2.1.5 → v2.2.0 ...
# Updated v2.1.5 → v2.2.0
```

### `portal version`

Print the currently installed version.

```bash
portal version
```

No flags. Outputs the version string (e.g., `v2.1.5`) and exits.

## Behavior Notes

- **Update notifications** - `portal expose` and `portal list` check for new releases in the background. The check runs at most once every 24 hours (cached locally) and never blocks command execution. When a newer version is found, a hint is printed to stderr after the command output.
- **Identity persistence** - `portal expose` loads or creates a signing identity at `identity.json` (or `--identity-path`). Reusing the same path keeps the same address across runs.
- **Multiple relays** - Multiple relay URLs are registered independently. Each relay gets its own lease. A relay going down does not stop healthy relays from serving.
- **Retry semantics** - Relay startup and reconnect failures are retried in the background. The tunnel starts as soon as relay URLs pass local validation.
- **Discovery expansion** - With discovery enabled, the tunnel consumes relay `/discovery` results and reconciles its relay pool. The SDK does not announce itself and does not serve discovery endpoints.
- **MITM enforcement** - Enabled by default. The TLS self-probe runs asynchronously after real connections begin, with a 30-second cooldown between probes.
- **503 on unreachable local service** - When the local target is unreachable, the tunnel returns an HTTP 503 page to the client.
- **HTTP route mode** - Cannot be combined with `--udp`. Routes are HTTP-only.
- **TCP port requirements** - `--tcp` requires the relay to have `TCP_ENABLED=true`, a valid `MIN_PORT/MAX_PORT` range, and TCP port enabled in the admin panel.
- **UDP requirements** - `--udp` requires the relay to have `UDP_ENABLED=true`, a valid `MIN_PORT/MAX_PORT` range, UDP enabled in the admin panel, and `SNI_PORT/udp` reachable for the QUIC backhaul.
- **Legacy CLI removed** - Bare `portal [flags]` is no longer accepted; use `portal expose` explicitly. `APP_*`, `RELAYS`, and `DEFAULT_RELAYS` environment variables are no longer used.

## Next Steps

- **[Getting Started](/getting-started)** - Quick tutorial for your first tunnel
- **[Concepts](/concepts)** - How Portal's encryption and relay model works
- **[Deployment](/deployment)** - Run your own relay server
