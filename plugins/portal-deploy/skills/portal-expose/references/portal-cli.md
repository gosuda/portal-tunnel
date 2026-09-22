# Portal CLI reference for app deployment

Last checked against `gosuda/portal-tunnel` main commit `d38001ad` on 2026-09-22. Prefer the behavior of the installed Portal version and the repository's current `docs/src/routes/cli-reference/+page.md` and `docs/src/routes/portal-agent/+page.md` when they differ from this snapshot.

## Installation

Check first:

```sh
command -v portal
portal version
```

Official Unix installer:

```sh
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

Official PowerShell installer:

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

Installation changes user or system paths. Obtain approval before running it. A relay also serves the same installer at `<relay>/api/install.sh` and `<relay>/api/install.ps1`; that is what its website's quick start shows, and it is fine for a relay the user chose. Do not substitute an installer hosted by a relay the user did not choose.

## Temporary exposure

`portal expose` defaults `--identity-path` to `identity.json` in the process working directory. That file is created automatically and contains private key material. Always pass an absolute path outside the repository. The `IDENTITY_PATH` environment variable sets the same flag, and the same variable name means the identity directory for `relay-server`; on a host that runs both, prefer the explicit flag.

An existing identity file supplies the saved public name as well as the key. `--name` applies only when a new identity is created and never renames an existing one, so use one identity file per public name.

Web app:

```sh
portal expose 3000 --identity-path "$HOME/Library/Application Support/Portal Tunnel/identities/preview.json"
portal expose 127.0.0.1:3000 --name my-app --identity-path /absolute/path/to/identity.json
```

On Linux, prefer `$XDG_CONFIG_HOME/portal-tunnel/identities/` or `~/.config/portal-tunnel/identities/`. Create the parent directory if needed.

Trusted static site or HTML entry:

```sh
portal expose --serve ./site --name my-app --identity-path /absolute/path/to/identity.json
portal expose --serve ./site/index.html --name my-app --identity-path /absolute/path/to/identity.json
```

Static serving follows symlinks inside the selected directory. Expose only a directory whose complete contents and symlink targets are intended to be public.

Multiple HTTP services:

```sh
portal expose --name my-app \
  --identity-path /absolute/path/to/identity.json \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Specific relay only:

```sh
portal expose 3000 \
  --identity-path /absolute/path/to/identity.json \
  --relays https://portal.example.com \
  --discovery=false
```

Unlisted on relay screens:

```sh
portal expose 3000 --hide --identity-path /absolute/path/to/identity.json
```

Fail-closed MITM handling:

```sh
portal expose 3000 --ban-mitm --identity-path /absolute/path/to/identity.json
```

Raw transport, only on explicit request:

```sh
portal expose 127.0.0.1:25565 --name game --tcp --identity-path /absolute/path/to/identity.json
portal expose 127.0.0.1:19132 --name game --udp --identity-path /absolute/path/to/identity.json
```

`--udp` adds a UDP relay on the default stream lease for the positional target. For a UDP-only request, the positional target must be that UDP service. `--udp-addr` is only for an explicit combined stream-plus-UDP request, for example `portal expose 127.0.0.1:8080 --udp --udp-addr 127.0.0.1:19132`. Do not point the positional target at an unrelated HTTP app just to attach UDP.

`--tcp` and `--udp` require relay-side support. `--http-route` cannot be combined with `--udp`; `--serve` cannot be combined with a target, HTTP routes, TCP, or UDP. `--cache` requires `--serve` and cannot be combined with `--ban-mitm`; `--cache-ttl` requires `--cache` and must be `0` or between `1s` and `8760h`.

### Flags

The flag is `--description`, not `--desc`. Environment variables in the third column set the same value.

| Flag | Default | Env | Meaning |
|------|---------|-----|---------|
| `--relays` | | | Additional relay API URLs, comma-separated; a missing scheme means https |
| `--discovery` | `true` | | Include bootstrap relays and discover more |
| `--overlay` | `false` | `OVERLAY_ENABLED` | Prefer IVNP overlay transport when available |
| `--ban-mitm` | `false` | `BAN_MITM` | Ban a relay when the self-probe detects TLS termination |
| `--identity-path` | `identity.json` | `IDENTITY_PATH` | Identity file, created when missing |
| `--identity-json` | | `IDENTITY_JSON` | In-memory identity JSON; wins over the file |
| `--name` | generated | | Public hostname prefix, one DNS label; applies only to a new identity |
| `--description`, `--tags`, `--owner`, `--thumbnail` | | | Public listing metadata; `--tags` is comma-separated |
| `--hide` | `false` | | Keep the service out of relay listings |
| `--http-route` | | | `PATH=UPSTREAM [METHOD[,METHOD...]:AMOUNT]`, repeatable |
| `--serve` | | | Serve a directory, or an HTML file as the SPA entry of its folder |
| `--cache` | `false` | | Let selected relays store `--serve` content and terminate browser TLS |
| `--cache-ttl` | `0` | | Requested offline cache lifetime; `0` uses relay policy |
| `--udp` | `false` | `UDP_ENABLED` | Add a public UDP relay |
| `--udp-addr` | the target | `UDP_ADDR` | Local UDP target when it differs from the positional target |
| `--tcp` | `false` | `TCP_ENABLED` | Request a dedicated raw TCP port, no TLS |
| `--max-active-relays` | `3` | `MAX_ACTIVE_RELAYS` | Cap on auto-selected relays kept connected |
| `--metrics-addr` | | | Serve Prometheus `/metrics` on `host:port` |
| `--x402-pay-to`, `--x402-network`, `--x402-asset`, `--x402-endpoint`, `--x402-testnet`, `--x402-facilitator-token` | | `CSPR_CLOUD_API_KEY` for the token | Paid routes; see `x402.md` |

`portal list` accepts `--relays` and `--default-relays` (default `true`) and prints one `RELAY  VERSION` row per resolved relay. It never lists services.

## Persistent agent

`portal agent run` without `--foreground` installs and starts a per-user OS service (launchd LaunchAgent or systemd user unit). Obtain approval before that path. `--foreground` keeps the agent in the current process and skips service installation.

`run`, `restart`, and `stop` are service-wide. They apply to every `[[tunnels]]` entry owned by that `service_name`. Do not point a second config at the default `portal-agent` service if an existing agent already has unrelated tunnels. An isolated agent also needs its own `state_dir` and loopback `control_addr`; those otherwise default to the shared data directory and `127.0.0.1:4018`.

`--foreground` skips OS-service installation, but if stdin and stdout are TTYs it then opens `portal agent dashboard`. Run it from a non-TTY session when the agent should stay in the background and emit logs.

`portal agent run` does not accept `--relays` or `--discovery`. Put those values on the tunnel entry. A tunnel entry is one of three modes: `target`, `http_routes`, or `serve` for a static site. Omit `identity_path` unless you have an absolute path outside the repository; an empty value stores identity under the agent state directory.

`portal agent dashboard` is an interactive TUI that owns the terminal until Ctrl+C. Do not run it from an agent session. Give the user the command.

Minimal config:

```toml
[agent]
control_addr = "127.0.0.1:4018"
service_name = "portal-agent"

[[tunnels]]
id = "web"
name = "my-app"
target = "127.0.0.1:3000"
discovery = true
description = "Managed web tunnel"
tags = ["web"]
```

Isolated second agent:

```toml
[agent]
control_addr = "127.0.0.1:4019"
service_name = "portal-agent-my-app"
state_dir = "/absolute/path/to/portal-agent-my-app"

[[tunnels]]
id = "web"
name = "my-app"
target = "127.0.0.1:3000"
```

User-selected relay, unlisted, fail-closed MITM:

```toml
[[tunnels]]
id = "web"
name = "my-app"
target = "127.0.0.1:3000"
relays = ["https://portal.example.com"]
discovery = false
hide = true
ban_mitm = true
```

Commands:

```sh
portal agent run --config /absolute/path/to/config.toml
portal agent run --foreground --config /absolute/path/to/config.toml
portal agent restart --config /absolute/path/to/config.toml
portal agent stop --config /absolute/path/to/config.toml
```

Handoff-only, do not execute in the agent session:

```sh
portal agent dashboard --state-dir /absolute/path/to/state
```

Keep `control_addr` on loopback.

Default config locations:

- Linux: `$XDG_CONFIG_HOME/portal-tunnel/agent/config.toml` or `~/.config/portal-tunnel/agent/config.toml`; as root, `/etc/portal-tunnel/agent/config.toml`
- macOS: `~/Library/Application Support/Portal Tunnel/Agent/config.toml`; as root, `/Library/Application Support/Portal Tunnel/Agent/config.toml`
- Windows: `%ProgramData%\Portal Tunnel\Agent\config.toml`

### Config keys

`[agent]`: `state_dir` (defaults to the platform data directory), `control_addr` (default `127.0.0.1:4018`), `service_name` (default `portal-agent`), `allowed_wallets` (wallet addresses allowed to sign in to the dashboard).

`[[tunnels]]`: `id`, `name`, `target`, `serve` (static site directory or HTML file, relative to the config file's directory; cannot be combined with `target`, `http_routes`, `tcp`, or `udp`; the relay cache options have no TOML equivalent), `http_routes` (entries with `prefix`, `upstream`, `methods`, `amount`), `relays`, `discovery`, `overlay`, `identity_path`, `identity_json`, `udp`, `udp_addr`, `tcp`, `ban_mitm`, `max_active_relays` (default `3`), `description`, `tags`, `owner`, `thumbnail`, `hide`, `x402_pay_to`, `x402_testnet`, `x402_network`, `x402_asset`, `x402_endpoints`, `x402_facilitator_token`. The keys mirror the `portal expose` flags one to one.

## Output and readiness

- A Portal process can start while relay discovery, lease registration, and reconnects continue in the background.
- HTTP readiness log: `service ready at <https-url>`.
- Raw TCP/UDP readiness log: `raw transport endpoints allocated` with `tcp_addr` and/or `udp_addr`. Do not wait for an HTTPS URL in that mode.
- Multiple relays can produce multiple public URLs. Report and verify each URL or raw endpoint that is handed off.
- Tenant TLS terminates locally through a keyless TLS 1.3 server: the relay signs each handshake with its certificate key but never receives the session keys. The hostname is still publicly reachable. Without `--hide`, anyone can enumerate the lease through `GET <relay>/api/state`, and relays that enable their directory page show it there as well. Portal does not add application authentication.
- The MITM self-probe runs against every relay whose tenant TLS stack exports keying material. `--ban-mitm` defaults to false. Without it, a mismatch is a warning and the tunnel keeps serving. With it, Portal bans the relay and closes that listener, and refuses at registration a relay that cannot export keying material. `--cache` disables the probe because it deliberately permits relay TLS termination; the two flags cannot be combined. A `self-probe timed out` or `self-probe failed` line is not a detection.
- A later log line starting `relay no longer active for <url>` retracts a previously ready URL.
