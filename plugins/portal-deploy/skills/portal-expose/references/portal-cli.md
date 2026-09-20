# Portal CLI reference for app deployment

Last checked against `gosuda/portal-tunnel` main commit `79ccc6f2388dd47b0121c4593746150e084f1785` on 2026-08-14. Prefer the behavior of the installed Portal version and the repository's current `cmd/portal-tunnel/README.md` when they differ from this snapshot.

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

Installation changes user or system paths. Obtain approval before running it. Do not substitute an installer hosted by an unverified relay.

## Temporary exposure

`portal expose` defaults `--identity-path` to `identity.json` in the process working directory. That file is created automatically and contains private key material. Always pass an absolute path outside the repository.

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

`--tcp` and `--udp` require relay-side support. `--http-route` cannot be combined with `--udp`; `--serve` cannot be combined with a target, HTTP routes, TCP, or UDP.

## Persistent agent

`portal agent run` without `--foreground` installs and starts a per-user OS service (launchd LaunchAgent or systemd user unit). Obtain approval before that path. `--foreground` keeps the agent in the current process and skips service installation.

`run`, `restart`, and `stop` are service-wide. They apply to every `[[tunnels]]` entry owned by that `service_name`. Do not point a second config at the default `portal-agent` service if an existing agent already has unrelated tunnels. An isolated agent also needs its own `state_dir` and loopback `control_addr`; those otherwise default to the shared data directory and `127.0.0.1:4018`.

`--foreground` skips OS-service installation, but if stdin and stdout are TTYs it then opens `portal agent dashboard`. Run it from a non-TTY session when the agent should stay in the background and emit logs.

`portal agent run` does not accept `--relays` or `--discovery`. Put those values on the tunnel entry. Omit `identity_path` unless you have an absolute path outside the repository; an empty value stores identity under the agent state directory.

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

Default user config locations:

- Linux: `$XDG_CONFIG_HOME/portal-tunnel/agent/config.toml` or `~/.config/portal-tunnel/agent/config.toml`
- macOS: `~/Library/Application Support/Portal Tunnel/Agent/config.toml`
- Windows: `%ProgramData%\Portal Tunnel\Agent\config.toml`

## Output and readiness

- A Portal process can start while relay discovery, lease registration, and reconnects continue in the background.
- HTTP readiness log: `service ready at <https-url>`.
- Raw TCP/UDP readiness log: `raw transport endpoints allocated` with `tcp_addr` and/or `udp_addr`. Do not wait for an HTTPS URL in that mode.
- Multiple relays can produce multiple public URLs. Report and verify each URL or raw endpoint that is handed off.
- Tenant TLS terminates locally, but the hostname is still publicly reachable. Without `--hide`, the lease is published on relay listing screens and `portal list` can enumerate it. Portal does not add application authentication.
- The MITM self-probe always runs. `--ban-mitm` defaults to false. Without it, a mismatch is a warning and the tunnel keeps serving. With it, Portal bans the relay and closes that listener. There is no flag that turns the probe off.
