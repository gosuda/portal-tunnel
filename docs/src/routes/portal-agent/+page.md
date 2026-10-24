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
auth = "siwe"
auth_allowed_wallets = ["0x1234..."]
auth_identity_headers = true
```

Static site config:

```toml
[[tunnels]]
id = "site"
name = "my-site"
serve = "./dist"
```

`serve` accepts a directory containing `index.html` or an HTML file such as
`./dist/main.html`. Relative paths resolve from the directory containing
`config.toml`. The file's parent directory is served when a file is selected;
unknown request paths fall back to the entry file, as with `portal expose --serve`.
The entry file must exist when the tunnel starts. Edit `serve` in TOML and
restart the tunnel or agent to change the site path.

Set `auth = "credential"` on a target, routed HTTP, or static tunnel for
Portal-native credentials, or use `auth = "siwe"` or `auth = "oidc"`.
`auth_allowed_wallets` restricts login to listed principals (Ethereum addresses for `siwe`, credential subjects for `credential`, or verified emails, `@example.com` domains, or `sub:` subjects for `oidc`). It is optional, except that `oidc` requires at least one entry.
`auth_identity_headers = true` injects the verified wallet address and `siwe`
for SIWE, the credential subject and `credential` for credential auth, or the
verified email (or `sub:` subject) and `oidc` for OIDC, as
`X-Portal-User` and `X-Portal-Auth`; Portal always strips client-supplied copies
first.

`oidc` also needs `auth_oidc_issuer` and `auth_oidc_client_id`, and accepts an optional `auth_oidc_client_secret`. The agent takes them from the tunnel config, not from the CLI's `AUTH_OIDC_*` variables:

```toml
[[tunnels]]
id = "web"
target = "127.0.0.1:3000"
auth = "oidc"
auth_oidc_issuer = "https://accounts.google.com"
auth_oidc_client_id = "<client-id>"
auth_allowed_wallets = ["alice@example.com"]
```

See [OpenID Connect](/siwe-authentication#openid-connect-oidc) for the redirect URI and allowlist rules.

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
x402_pay_to = "0x..."
x402_testnet = true

[[tunnels.http_routes]]
prefix = "/api"
upstream = "http://127.0.0.1:3001"
methods = ["GET"]
amount = "0.01"

[[tunnels.http_routes]]
prefix = "/"
upstream = "http://127.0.0.1:5173"
```

For Casper, replace the Sui payment fields with:

```toml
x402_network = "casper:casper-test"
x402_asset = "hash-..."
x402_pay_to = "account-hash-..."
x402_endpoints = ["https://x402-facilitator.cspr.cloud"]
```

Set `CSPR_CLOUD_API_KEY` in the agent service environment for the hosted
CSPR.cloud facilitator. If the service cannot receive that environment
variable, set `x402_facilitator_token` in this tunnel's TOML instead. Custom
facilitators that do not require authentication can omit both.

If a route has `amount`, the tunnel serves `/x402/client.js` and
`/x402/prepare` on the public tunnel origin for the Sui wallet flow. Casper
clients consume the protected route's 402 requirements, sign with an external
Casper x402 SDK, and retry with `PAYMENT-SIGNATURE` or `X-PAYMENT`. The tunnel
still verifies and settles payment before proxying the paid route.

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

### Docker Compose TUI

See the [Portal CLI Docker Compose instructions](https://github.com/gosuda/portal-tunnel/blob/main/cmd/portal-tunnel/README.md#agent-dashboard-tui)
for the single maintained setup, including persistent agent state and host
directory permissions.

## Remote Access to a Home Service

This example exposes one HTTP service on your home network, here Home Assistant at `192.168.1.20:8123`, to a browser outside the home. Visitors pass a credential login first, so no VPN app is needed on the phone. Prepare the `./identity` directory as described in the [Docker Compose steps](https://github.com/gosuda/portal-tunnel/blob/main/cmd/portal-tunnel/README.md#docker-compose).

Save this as `./identity/config.toml`:

```toml
[agent]
state_dir = "/identity"
control_addr = "127.0.0.1:4018"

[[tunnels]]
id = "homeassistant"
name = "home-ha"
target = "192.168.1.20:8123"
relays = ["https://relay.example.com"]
discovery = false
ban_mitm = true
hide = true
auth = "credential"
auth_allowed_wallets = ["alice-phone"]
```

- `target` must be an address the agent container can reach. Inside a bridge-network container `127.0.0.1` is the container itself, not your server.
- Choose the relay yourself: the relay holds its domain's certificate key (see the [security model](https://gosuda.github.io/portal-tunnel/security-model#relay-trust-reduction)). Pinning one relay also keeps the public URL from moving between relays.

Run the agent:

```yaml
services:
  portal-agent:
    image: ghcr.io/gosuda/portal-tunnel:latest
    command: ["agent", "run", "--config", "/identity/config.toml", "--foreground"]
    volumes:
      - ./identity:/identity
    restart: unless-stopped
```

The hostname is derived from the identity in `./identity/identity.json`, so it stays the same across restarts while that file persists. Copy the published hostname from the agent log. Credentials are bound to the hostname they are issued for, so use the one you will open:

```bash
docker compose logs portal-agent | grep "service ready at"
docker compose exec portal-agent /usr/bin/portal auth issue <published-hostname> \
  --identity-path /identity/identity.json \
  --subject alice-phone \
  --expires 720h
```

With a single tunnel the identity is `/identity/identity.json`; with several tunnels each one uses `/identity/<tunnel-id>/identity.json`.

Open the printed `https://.../_portal/auth/login#credential=pcred_...` URL on the phone. The credential stays in the URL fragment and is exchanged for an `HttpOnly`, `Secure` session cookie. Requests without a valid session are redirected to the login page and never reach Home Assistant, which still shows its own login afterwards.

### Home Assistant proxy settings

Home Assistant answers `400 Bad Request` to proxied requests until it trusts the proxy.

- Home Assistant 2026.8 and later: in **Settings > System > Network > HTTP server**, enable **Trust X-Forwarded-For** and add the proxy address under **Trusted proxies**. Saving restarts Home Assistant; confirm the change within five minutes or it reverts.
- Earlier versions: set `use_x_forwarded_for: true` and `trusted_proxies` under `http:` in `configuration.yaml`.

Use the address Home Assistant sees the agent connect from. If Home Assistant itself runs in Docker behind a published port, that is the Docker network gateway (for example `172.22.0.1`), and the log line `Received X-Forwarded-For header from an untrusted proxy <address>` names it. Add that single address, not a whole subnet. Behind a gateway address every device on the LAN looks like the proxy, so do not combine this with IP-based login such as `trusted_networks`.

### Revoking access

Remove a subject from `auth_allowed_wallets` and restart the agent: its credentials and active sessions stop working. Re-adding the same subject revives its unexpired credentials, so issue a new subject name (for example `alice-phone-2`) instead.

An empty `auth_allowed_wallets` list means any validly signed credential or session is accepted, so removing the last subject does **not** revoke anything. To revoke the last user, stop and remove the tunnel (or delete its identity file, which invalidates every credential issued for it).

## Dashboard

The dashboard is a local terminal UI drawn like a text-mode terminal, in amber
by default. It polls agent status every two seconds and edits the same TOML
config file that the service uses. It is laid out for a terminal of at least
80 columns by 24 rows and uses the extra room of a larger one.

For a ready named tunnel, the Relays pane displays and opens the short URL
without an Ethereum address when the relay granted that name. Otherwise it uses
the identity-bound URL. `/agent/status` keeps `public_url` as the identity-bound
URL and includes `alias_url` only for a ready relay with an assigned short name.

Dashboard panes:

| Pane | Purpose |
|------|---------|
| Tunnels | Add, select, and delete tunnels |
| Settings | Edit max active relays and public metadata |
| Relays | Connect or disconnect relays for the selected tunnel |

The active pane has its title in brackets and gets the most rows; the other
panes shrink to a few rows until you switch to them. Each tunnel row starts
with a status LED, explained in the legend beside the panes:

| LED | State |
|-----|-------|
| `[*]` | running |
| `[~]` | starting |
| `[ ]` | stopped |
| `[!]` | error |

The bar at the bottom lists the keys that work in the active pane and state.
Terminals such as macOS Terminal often keep function keys for themselves, so
every function key has a letter or key alias:

| Key | Action |
|-----|--------|
| `F2` / `a` | Open the Add Tunnel form; in the form, `F2` or `enter` creates the tunnel |
| `tab` / `shift+tab`, `left` / `right` | Switch panes |
| `up` / `down` | Move within the active pane or between form fields |
| `enter` | Apply the Settings, create the tunnel in the form, or connect the selected relay in the Relays pane |
| `F8` / `delete` | In the Tunnels pane, delete the selected tunnel after you confirm with `y`; `n` or `esc` keeps it |
| `c` | Connect the selected relay in the Relays pane |
| `d` / `delete` | Disconnect the selected relay in the Relays pane |
| `o` | Open the selected public tunnel URL |
| `esc` | Cancel the form or a question, or return to the Tunnels pane |
| `F10` / `q` / `ctrl+c` | Exit the dashboard |

In the Settings pane and in the Add Tunnel form, `tab` and `shift+tab` move
between fields, so only `left` and `right` switch panes there, and `q` and `a`
are typed into the field. The mouse still works: click a pane title, a row, a
field, or a button.

The Add Tunnel action (`F2`, `a`, or the button) opens a form. Fill either
`Target` for a simple loopback tunnel or `Routes` for routed HTTP. Routes use
this syntax:

```text
/paid=3001 GET:0.01; /=5173
```

Each entry is `PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]`. Fill `X402 Pay
To` when any route has an amount. Sui uses `X402 Testnet`; Casper additionally
uses `X402 Network`, `X402 Asset`, and optionally its facilitator in `X402 Endpoints`.
The form also accepts explicit `Relays`,
`Discovery`, and `Max Relays`; max relays caps auto-selected discovery relays
while explicit relays are still included.

After creation, routed HTTP paths, x402 payment amounts, payment network, and
discovery mode are read-only in the Settings pane. To change routes, payment
amounts, payment network, or discovery mode, edit `http_routes`,
`x402_pay_to`, `x402_testnet`, `x402_network`, `x402_asset`, `x402_endpoints`,
and `discovery` in `config.toml`, then restart
the agent or tunnel. Other advanced options such as UDP, TCP, or custom
identity JSON are also configured in
`config.toml`.

### Theme and terminal support

Choose the palette with `--theme amber` (the default) or `--theme green` on
`portal agent dashboard`, or with the `PORTAL_TUI_THEME` environment variable;
the flag wins. `portal agent run --foreground` opens the same dashboard and
accepts the same flag; without a terminal it runs the agent without the
dashboard and does not check the theme. Both palettes are made for a dark
terminal background.

Colors are ANSI-256 values that fall back to the 16 ANSI colors on simpler
terminals. With `NO_COLOR` set the dashboard uses no color at all and every
state is still told apart by its glyph and text.

The frames use box-drawing characters. When `TERM` is `dumb` or `linux`, or
when `LC_ALL`, `LC_CTYPE`, and `LANG` do not name a UTF-8 locale, the dashboard
draws ASCII frames with `+`, `-`, `|`, and `=` instead. A minimal container
often has no locale set; export `LANG=C.UTF-8` there to get the box-drawing
frames.

## Tunnel Config Fields

Common fields:

| Field | Description |
|-------|-------------|
| `id` | Stable local tunnel ID used by the dashboard and control API |
| `name` | Public lease name, used as the subdomain label |
| `target` | Local TCP target, equivalent to `portal expose <target>` |
| `http_routes` | Routed HTTP mappings; cannot be combined with `target`, `serve`, `tcp`, or `udp` |
| `serve` | Static site directory or HTML file; relative to the config file's directory |
| `relays` | Explicit relay API URLs |
| `discovery` | Include registry and relay discovery expansion |
| `max_active_relays` | Maximum auto-selected relays kept connected; explicit relays are always included |
| `overlay` | Prefer an [IVNP overlay path](/concepts#ivnp-backed-overlay-networking) when available; defaults to direct and retains direct fallback |
| `identity_path` | Tunnel identity JSON path |
| `identity_json` | In-memory identity JSON; takes precedence over `identity_path` without reading or writing that file |
| `udp`, `udp_addr` | UDP transport settings |
| `tcp` | Dedicated raw TCP port setting |
| `ban_mitm` | Ban relays when the TLS self-probe detects termination; defaults to warning-only |
| `description`, `tags`, `owner`, `thumbnail`, `hide` | Public relay metadata |
| `auth` | Application login provider: `siwe`, `credential`, or `oidc` |
| `auth_allowed_wallets` | Principals allowed to sign in (Ethereum wallets for `siwe`, subjects for `credential`, or verified emails, `@example.com` domains, or `sub:` subjects for `oidc`); empty allows any valid principal, except for `oidc`, which requires at least one entry; requires `auth` when set |
| `auth_oidc_issuer` | OIDC issuer URL; required when `auth = "oidc"` |
| `auth_oidc_client_id` | OIDC client ID; required when `auth = "oidc"` |
| `auth_oidc_client_secret` | Optional OIDC client secret for `auth = "oidc"` |
| `auth_identity_headers` | Inject verified Portal identity headers into upstream requests |
| `x402_pay_to` | Payment recipient for paid HTTP routes |
| `x402_testnet` | Use Sui testnet when `x402_network` is omitted |
| `x402_network` | Optional Sui or Casper CAIP-2 network |
| `x402_asset` | wCSPR CEP-18 contract hash required by Casper |
| `x402_endpoints` | Optional Sui RPC endpoints or Casper facilitator URL |
| `x402_facilitator_token` | Casper facilitator token; falls back to `CSPR_CLOUD_API_KEY` |
| `http_routes[].amount` | Optional human payment amount, such as `0.01`, for one HTTP route prefix |
| `http_routes[].methods` | Optional HTTP methods that require payment on that route; empty means every method |

The agent supports target, routed HTTP, and static site modes. The CLI relay
cache options `cache` and `cache_ttl` are not supported in agent TOML.

Constraints:

- `target` cannot be combined with `http_routes`.
- `serve` cannot be combined with `target`, `http_routes`, `tcp`, or `udp`.
- `http_routes` cannot be combined with `tcp` or `udp`.
- Application auth cannot be combined with `tcp` or `udp`; `auth_allowed_wallets`, `auth_identity_headers`, and the `auth_oidc_*` fields require `auth`, and the `auth_oidc_*` fields require `auth = "oidc"`.
- `http_routes[].amount` requires `x402_pay_to`.
- `http_routes[].methods` requires `http_routes[].amount`.

## Identity Layout

If `identity_path` is omitted:

- a single tunnel uses `<state_dir>/identity.json`
- multiple tunnels use `<state_dir>/<tunnel-id>/identity.json`

An existing identity file or `identity_json` supplies its saved name and key;
`tunnels.name` is used only when creating a new identity.

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

On Windows, the default service runs as LocalSystem and restricts its state,
config, and control token to SYSTEM and Administrators. Run dashboard and other
service-control CLI commands from an elevated terminal. A foreground agent uses
the account that launched it; its secrets also allow that account.

Custom identity paths must use a directory that other users cannot modify.
Portal protects the identity file's ACL but does not change the permissions of
an arbitrary parent directory.

The agent refuses non-loopback `control_addr` values. Use `127.0.0.1`,
`localhost`, or another loopback address.

Control endpoints:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/agent/status` | Bearer token or wallet session | Read agent and tunnel status |
| `POST` | `/agent/shutdown` | Bearer token | Ask the agent to stop |
| `POST` | `/agent/tunnels` | Bearer token | Add a tunnel |
| `PATCH` | `/agent/tunnels/{id}` | Bearer token | Update metadata or max active relays |
| `DELETE` | `/agent/tunnels/{id}` | Bearer token | Delete a tunnel |
| `POST` | `/agent/tunnels/{id}/relays` | Bearer token | Connect a relay |
| `DELETE` | `/agent/tunnels/{id}/relays` | Bearer token | Disconnect a relay |

Wallet auth endpoints also exist under `/agent/auth/*`. Wallet-authenticated
requests are read-only and can only call `/agent/status`; mutating operations
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
Common causes are an invalid local target, a relay URL that cannot be reached,
or a transport disabled on the relay.

## Next Steps

- [Configuration Reference](/configuration#configtoml): every agent config field
- [Wallet and ENS](/wallet-and-ens): admin tokens, wallet auth, and ENS gasless behavior
- [CLI Reference](/cli-reference): command flags and examples
