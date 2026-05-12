# Portal CLI

`cmd/portal-tunnel` builds the `portal` CLI. It connects local services to
Portal relays without requiring inbound firewall rules, port forwarding, or
manual DNS setup.

Portal's default model is intentionally simple:

- The relay owns transport, lease registration, routing, and relay policy.
- The tunnel process owns the exposed endpoint behavior.
- In the default HTTPS stream path, tenant TLS terminates in the tunnel process,
  not at the relay.
- In routed HTTP mode, the tunnel process runs the HTTP reverse proxy. The relay
  is still not an HTTP proxy.
- In raw TCP and UDP modes, the relay allocates public transport endpoints and
  forwards traffic to the tunnel process.

## Install

Install directly from the official GitHub release assets:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
portal list
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
portal list
```

If your relay publishes its own installer, use that relay instead:

```bash
curl -sSL https://portal.example.com/install.sh | bash
portal expose 3000 --relays https://portal.example.com --discovery=false
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://portal.example.com/install.ps1 | iex
portal expose 3000 --relays https://portal.example.com --discovery=false
```

## Choosing A Mode

Use the default stream mode for most local web apps:

```text
portal expose 3000 --name myapp
```

This publishes `myapp.<relay-root-host>` as HTTPS. The relay routes by SNI and
bridges the connection to the tunnel process. The tunnel process performs the
tenant TLS handshake locally and then proxies the byte stream to
`127.0.0.1:3000`.

Use routed HTTP mode when one public URL should mount multiple local HTTP
services:

```text
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

This is a tunnel-controlled HTTP reverse proxy. The relay still only transports
connections. Because the tunnel process parses HTTP in this mode, this is the
right mode for HTTP-specific behavior such as path routing, response header
policy, redirect rewriting, and cookie path remapping.

Use dedicated raw TCP mode for non-HTTP services that need a public TCP port:

```text
portal expose localhost:25565 --name minecraft --tcp
```

The relay allocates a TCP port from its configured port range and bridges raw
TCP to the local target. This path does not add TLS; use application-level
encryption when the protocol needs confidentiality.

Use UDP mode when the service needs a public UDP port:

```text
portal expose localhost:8080 --udp --udp-addr localhost:19132 --name game
```

The primary target still receives stream traffic. UDP datagrams are forwarded to
`--udp-addr`; when omitted, UDP uses the primary target.

## Relay And SEO Boundaries

The relay cannot safely inject HTTP headers, `robots.txt`, `noindex`, or content
policy into the default passthrough stream path. It does not own the HTTP
response body, and it is not supposed to terminate tenant TLS.

If a relay is used as a public multi-tenant service, do not put arbitrary user
tunnels under a brand domain that also carries first-party SEO value. Use a
separate tunnel domain for shared wildcard leases, and keep brand, docs, admin,
and product pages on first-party hosts.

Routed HTTP mode can enforce HTTP policy only inside cooperating tunnel
processes. It is useful for product features, but it is not a substitute for
domain separation because users can still choose the default passthrough path.

## Commands

### `portal expose [flags] <target>`

Expose one local target through the default stream path.

```text
portal expose 3000
portal expose localhost:8080 --name myapp
portal expose http://127.0.0.1:8080 --name local-http
```

`<target>` accepts:

- a bare port, such as `3000`
- a `host:port`
- an `http://host:port` or `https://host:port` URL

Bare ports resolve to `127.0.0.1:<port>`. URL inputs are accepted for address
parsing only; paths, queries, and fragments are not supported.

Instead of `<target>`, repeat `--http-route PATH=UPSTREAM` to run routed HTTP
mode:

```text
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Route matching is longest-prefix-first. A route like
`/api=http://127.0.0.1:3001` matches `/api/*` and strips the `/api` prefix before
proxying to the upstream.

Routed HTTP mode automatically:

- forwards `X-Forwarded-*`
- rewrites matching upstream `Location` redirects back to the public route path
- strips loopback cookie domains
- remaps cookie paths to the mounted route prefix

Mode constraints:

- `<target>` cannot be combined with `--http-route`.
- `--http-route` cannot be combined with `--udp`.
- Multi-hop currently supports only the default SNI TLS stream transport.
- `--multi-hop` cannot be combined with automatic `--multi-hop-depth`.

- `<target>` accepts a bare port like `3000`, a `host:port`, or an `http(s)://host:port` URL.
- Bare ports resolve to `127.0.0.1:<port>`.
- Instead of `<target>`, you can repeat `--http-route PATH=UPSTREAM` to aggregate multiple local HTTP services behind one public URL.
- Route matching is longest-prefix-first. `/api=http://127.0.0.1:3001` matches `/api/*` and strips the `/api` prefix before proxying to the upstream.
- Routed HTTP mode automatically forwards `X-Forwarded-*`, rewrites upstream `Location` redirects back to the public route path, and strips loopback cookie domains while remapping cookie paths to the mounted route prefix.
- `--name` is optional. When omitted, the CLI generates a name for that run.
- `--relays` adds explicit relay API URLs for that run. Explicit relays are always kept connected and are not counted against `--max-active-relays`.
- `--multi-hop` sets one ordered multi-hop relay path for that run.
- `--multi-hop-depth` automatically selects one multi-hop relay path with that hop count.
- `--pepper` opts into the optional pepper layer for multi-hop runs. Omit it to keep pepper disabled. `passive` preserves current behavior. `active` is fail-closed and only starts with automatic `--multi-hop-depth 2+`, discovery enabled, an ephemeral per-run identity, sufficient system entropy, and randomized bridge entry selection; explicit `--multi-hop` paths and supplied identity JSON are rejected.
- `--discovery=false` disables the public registry seed list and the runtime relay discovery expansion loop for that run. With `--discovery=false`, only the explicit `--relays` values are used.
- `--ban-mitm` enables strict rejection when the TLS self-probe detects termination in the path.
- `--tcp` requests a dedicated TCP port on the relay for raw TCP services that do not use TLS (e.g., Minecraft, game servers).
- `--udp` requests a public UDP port on the relay and forwards datagrams to `--udp-addr` or the primary target.

Flags:

```text
--relays          Portal relay API URLs (comma-separated, https only)
--multi-hop       Ordered multi-hop relay API URLs, comma-separated
--multi-hop-depth Automatically select one multi-hop route with this hop count; 0 or 1 disables multi-hop
--pepper          Optional pepper mode: active or passive; omitted disables the pepper layer
--discovery       Include public registry relays and discover additional relay bootstraps
--max-active-relays  Maximum number of auto-selected relays; explicit --relays are always included
--ban-mitm        Ban relay when the MITM self-probe detects TLS termination
--identity-path   Identity JSON file path; created automatically when missing
--identity-json   Identity JSON payload; overrides --identity-path contents and is persisted there when both are set
--name            Public hostname prefix (single DNS label); auto-generated when omitted
--description     Service description metadata
--tags            Service tags metadata (comma-separated)
--thumbnail       Service thumbnail URL metadata
--owner           Service owner metadata
--hide            Hide service from relay listing screens
--tcp        Request a dedicated TCP port on the relay for raw TCP services (no TLS)
--udp        Enable public UDP relay in addition to the default stream path
--udp-addr   Local UDP target address; defaults to the primary target when --udp is enabled
--http-route      HTTP route mapping in PATH=UPSTREAM form; repeat for multiple routes
```

### `portal list [flags]`

Print the relay URLs that the CLI will use for the current invocation.

```text
portal list
portal list --relays https://portal.example.com --default-relays=false
```

`portal list` resolves the registry seed list plus explicit relays. Unlike
`portal expose`, it does not run the runtime relay discovery expansion loop.

### `portal agent run [flags]`

Run Portal as a managed long-lived tunnel agent.

```text
portal agent run
portal agent dashboard
portal agent stop
portal agent restart
```

The agent service owns multiple tunnel definitions from one config file. The
local control API binds to loopback and is authenticated with a token stored in
the agent state directory.

Useful commands:

- `portal agent run` reads the platform default config path, installs or updates
  the OS service, starts it in the background, and exits after the agent is ready.
- `portal agent run --config config.toml --foreground` runs the agent in the
  current terminal and opens the dashboard when the terminal is interactive.
- `portal agent dashboard` attaches to a running agent and opens the local TUI.
- `portal agent stop` asks the local agent to shut down, then disables or stops
  the OS service so intentional shutdown is not immediately restarted.
- `portal agent restart` stops the running agent if present, installs or updates
  the service from the existing config, and starts it again.

`portal agent run`, `stop`, and `restart` require an existing config file.
`portal agent dashboard` can attach with only the default state directory or an
explicit `--state-dir`.

Default paths:

| OS | Config | Default identity |
|----|--------|------------------|
| Linux user | `$XDG_CONFIG_HOME/portal-tunnel/agent/config.toml` or `~/.config/portal-tunnel/agent/config.toml` | `$XDG_DATA_HOME/portal-tunnel/agent/identity.json` or `~/.local/share/portal-tunnel/agent/identity.json` |
| Linux root | `/etc/portal-tunnel/agent/config.toml` | `/var/lib/portal-tunnel/agent/identity.json` |
| macOS user | `~/Library/Application Support/Portal Tunnel/Agent/config.toml` | `~/Library/Application Support/Portal Tunnel/Agent/identity.json` |
| macOS root | `/Library/Application Support/Portal Tunnel/Agent/config.toml` | `/Library/Application Support/Portal Tunnel/Agent/identity.json` |
| Windows | `%ProgramData%\Portal Tunnel\Agent\config.toml` | `%ProgramData%\Portal Tunnel\Agent\identity.json` |

Example `config.toml`:

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

[[tunnels]]
id = "frontend"
name = "myapp-http"
relays = ["https://portal.example.com"]
discovery = false
http_routes = [
  { prefix = "/api", upstream = "http://127.0.0.1:3001" },
  { prefix = "/", upstream = "http://127.0.0.1:5173" },
]
```

## Install Behavior

- `install.sh` installs the downloaded binary as `portal`.
- `install.ps1` installs `portal.exe` for the current Windows user and updates
  the user `PATH`.
- The installer does not write a config file.
- `portal expose 3000` works after install because discovery is enabled by
  default.
- To target only a specific relay, use
  `--relays https://portal.example.com --discovery=false`.

## Operational Notes

- `portal expose` loads or creates the signing identity at `identity.json` by
  default.
- Reusing the same `--identity-path` keeps the same tunnel address across runs.
- Use different `--identity-path` values when you want separate local identities.
- Relay publishes each default stream service at `<name>.<portal-root-host>`.
- Multiple relay URLs are registered independently. Each relay gets its own
  lease registration and public URL.
- The tunnel consumes one aggregate SDK listener; the CLI does not run per-relay
  listener loops itself.
- Relay startup and reconnect failures are retried independently in the
  background. One unhealthy relay does not stop healthy relays from serving.
- The tunnel starts once relay URLs pass local validation. Remote compatibility
  checks, lease registration, and reconnects continue in the background until
  each relay becomes ready.
- With discovery enabled, the tunnel uses the public registry as discovery seed
  input and can expand through relay discovery.
- Explicit `--relays` values are always included separately from the
  auto-selected relay pool.
- With `--discovery=false`, only explicit relay URLs are used.
- Published public URLs appear only for relays that register successfully.
- Explicit relay listeners retry indefinitely. Auto-selected discovery relays
  are dropped from the active set after their retry budget is exhausted.
- Tenant TLS is provisioned automatically through the relay keyless signer. The
  SDK fetches the relay certificate chain and uses `/v1/sign` for remote signing.
- `portal expose` enables MITM strict enforcement by default. Use
  `--ban-mitm=false` for warning-only behavior.
- When the local stream target is unreachable, the tunnel returns an HTTP 503
  page to browser-style clients.
- `--tcp` requires the relay to have TCP port transport enabled and a valid
  `MIN_PORT`/`MAX_PORT` range.
- `--udp` requires the relay to have UDP transport enabled and a valid
  `MIN_PORT`/`MAX_PORT` range.

## Compatibility Notes

- Use `portal expose ...` explicitly; bare `portal [flags]` is not accepted.
- Runtime `APP_*`, `RELAYS`, and `DEFAULT_RELAYS` environment variable fallbacks
  are not used.
- Pass either a positional local target or repeat `--http-route`; do not use
  both in the same tunnel.
