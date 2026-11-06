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
Portal-native credentials, or use `auth = "siwe"`, `auth = "oidc"`, `auth = "saml"` or `auth = "email"`.
`auth_allowed_wallets` restricts login for `siwe` (Ethereum addresses) and `credential` (credential subjects), and it is optional. `auth_email_list` is the list for `oidc` and `saml` (verified emails, `@example.com` domains, or `sub:` subjects) and `email` (emails and `@example.com` domains), which require at least one entry.
`auth_identity_headers = true` injects the verified wallet address and `siwe`
for SIWE, the credential subject and `credential` for credential auth, the
verified email (or `sub:` subject) and `oidc` or `saml` for OIDC or SAML, or the
email address and `email` for email links, as
`X-Portal-User` and `X-Portal-Auth`; Portal always strips client-supplied copies
first. An agent tunnel cannot send the `X-Portal-Proof` identity proof yet: the
tunnel config has no key for it, and the agent does not read the CLI's
`AUTH_IDENTITY_PROOF` variable. When the application needs to verify the
identity headers, run the tunnel with `portal expose` and `AUTH_IDENTITY_PROOF`
instead ([details](/siwe-authentication#verifying-the-identity-headers)).

`oidc` also needs `auth_oidc_issuer` and `auth_oidc_client_id`, and accepts an optional `auth_oidc_client_secret`. The agent takes them from the tunnel config, not from the CLI's `AUTH_OIDC_*` variables:

```toml
[[tunnels]]
id = "web"
target = "127.0.0.1:3000"
auth = "oidc"
auth_oidc_issuer = "https://accounts.google.com"
auth_oidc_client_id = "<client-id>"
auth_email_list = ["alice@example.com"]
```

See [OpenID Connect](/siwe-authentication#openid-connect-oidc) for the redirect URI and allowlist rules.

`saml` needs `auth_saml_metadata_url`, or `auth_saml_metadata_file` for an identity provider that publishes no metadata URL. A relative file path is read from the directory of `config.toml`. `auth_saml_entity_id` and `auth_saml_subject_attribute` are optional. The agent takes them from the tunnel config, not from the CLI's `AUTH_SAML_*` variables:

```toml
[[tunnels]]
id = "web"
target = "127.0.0.1:3000"
auth = "saml"
auth_saml_metadata_url = "https://idp.example.com/realms/main/protocol/saml/descriptor"
auth_email_list = ["@example.com"]
```

See [SAML 2.0](/siwe-authentication#saml-20) for the ACS and metadata addresses and the allowlist rules.

`email` needs `auth_smtp_addr` and `auth_smtp_from`. Set `auth_smtp_username` and `auth_smtp_password` together for an SMTP server that requires a login. Each tunnel holds its own SMTP settings, so two email tunnels repeat them. The agent takes them from the tunnel config, not from the CLI's `AUTH_SMTP_*` variables:

```toml
[[tunnels]]
id = "web"
target = "127.0.0.1:3000"
auth = "email"
auth_smtp_addr = "smtp.gmail.com:587"
auth_smtp_username = "you@gmail.com"
auth_smtp_password = "<app-password>"
auth_smtp_from = "you@gmail.com"
auth_email_list = ["alice@example.com", "@example.com"]
```

See [Email links](/siwe-authentication#email-links) for the transport, the limits and the link rules.

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
It includes `approval` as `pending` or `refused` while the relay refuses the
tunnel. Its absence does not mean approved.

Dashboard panes:

| Pane | Purpose |
|------|---------|
| Tunnels | Add, select, and delete tunnels |
| Settings | Edit max active relays and public metadata, and see how the tunnel is protected |
| Relays | Connect or disconnect relays for the selected tunnel. `waiting` means waiting for relay approval, and `refused` means refused by relay |

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
| `F4` / `s` | Open the Access screen of the selected tunnel (only `F4` in the Settings pane, where `s` is typed) |
| `F8` / `delete` | In the Tunnels pane, delete the selected tunnel after you confirm with `y`; `n`, `esc`, `q` or `F10` keeps it |
| `c` | Connect the selected relay in the Relays pane |
| `d` / `delete` | Disconnect the selected relay in the Relays pane |
| `o` | Open the selected public tunnel URL |
| `esc` | Cancel the form or a question, or return to the Tunnels pane |
| `F10` / `q` / `ctrl+c` | Exit the dashboard. Under `portal agent run --foreground` this also stops the agent and every tunnel, so `F10` and `q` ask first (`y` stops it, `n`, `esc`, `q` or `F10` keeps it running) and `ctrl+c` stops it at once |

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

### Access screen

The Settings pane shows how the selected tunnel's public address is protected:
open to anyone, `credential`, wallet (`siwe`), `oidc`, `saml`, or `email`, with
the allow list, the identity headers and, for OIDC, the issuer, the client ID,
and whether a client secret is stored, for SAML, the metadata source, the entity
ID, and the subject, or, for email, the SMTP server, the sender, the SMTP
username, and whether an SMTP password is stored. OIDC, SAML and email also show
the result of the provider check made when the tunnel started. An empty allow
list means any valid credential or wallet for `credential` and `siwe`, so
removing the last entry opens the tunnel to all of them; `oidc`, `saml` and
`email` need at least one entry.

`F4`, `s`, or the Access button in the Settings pane opens the Access screen in
place of the panes to change these settings. The Mode row picks the provider;
the other rows are the allow list, an input for the next entry (a wallet address
for `siwe`, a subject for `credential`, an email, `@example.com` for a domain,
or `sub:<id>` for `oidc` and `saml`, or an email or `@example.com` for `email`),
the identity headers, and the OIDC issuer, client ID, and client secret, the
SAML metadata URL or file, entity ID, and subject attribute, or the SMTP server,
sender, SMTP username, and SMTP password. A tunnel that stays on its provider
keeps the list key it already stores. The screen writes `auth_email_list` for a
new `oidc`, `saml` or `email` tunnel, and when a tunnel changes to one of them.

| Key | Action |
|-----|--------|
| `left` / `right` | Change the mode, or turn the identity headers on or off |
| `up` / `down`, `tab` / `shift+tab` | Move between rows |
| `enter` | In the entry input, add the entry to the allow list; on the other rows, apply |
| `F2` | Apply from any row |
| `delete` / `backspace` | Remove the selected allow list entry |
| `F3` / `ctrl+r` | Show or hide the client secret or SMTP password you typed |
| `F6` / `ctrl+x` | Mark the stored client secret or SMTP password for removal, with the SMTP username it is paired with, or take the mark back (typing a secret takes the mark back, and marking drops what was typed) |
| `esc` | Cancel and close the screen |

An entry is checked and normalized as you add it. The client secret and the SMTP
password are typed hidden, one `•` (`*` in the ASCII fallback) per character, and
the screen only ever says whether a secret is stored. An empty secret input leaves the stored
secret as it is. Applying sends one `PATCH /agent/tunnels/{id}` that names only
what changed. The agent restarts the tunnel because the sign-in gate is built
when the tunnel starts, and the tunnel comes back without the relays connected
to it from the Relays pane, which are not saved in `config.toml`. The screen
stays open and says Applied once the next status shows the new settings,
including a new provider check. If the agent refuses the change, for example an
OIDC, SAML or email tunnel without an allow list entry, its message shows on the screen, the
typed secret stays so that you can correct the rest, and nothing is changed.
The typed secret is dropped when the screen closes, when the mode changes, and
after a successful apply. While nothing differs from what is stored the Apply
button is disabled, and it reads Applied only after an apply of this screen's
own. One apply runs at a time: the button reads Applying... until the agent
answers, and the agent restarts the tunnel before it does. If the agent does not
answer in time the screen says so; the change may still be applied, and the next
status shows it. If the tunnel's sign-in settings change while the
screen is open (`config.toml`, the CLI, another dashboard, or your own apply
while you kept editing), the screen shows the stored settings again, drops what
you had edited, and says so, so that applying cannot put the old values back;
open the screen again to continue from what is stored.

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
| `auth` | Application login provider: `siwe`, `credential`, `oidc`, `saml`, or `email` |
| `auth_allowed_wallets` | Principals allowed to sign in with `siwe` (Ethereum wallets) or `credential` (subjects); empty allows any valid principal; `oidc` and `saml` also read it, as `auth_email_list`; requires `auth` when set |
| `auth_email_list` | Who may sign in with `oidc` or `saml` (verified emails, `@example.com` domains, or `sub:` subjects) or `email` (emails and `@example.com` domains); at least one entry is required; requires `auth` when set |
| `auth_oidc_issuer` | OIDC issuer URL; required when `auth = "oidc"` |
| `auth_oidc_client_id` | OIDC client ID; required when `auth = "oidc"` |
| `auth_oidc_client_secret` | Optional OIDC client secret for `auth = "oidc"` |
| `auth_saml_metadata_url` | SAML identity provider metadata URL; `auth = "saml"` needs it or `auth_saml_metadata_file` |
| `auth_saml_metadata_file` | SAML identity provider metadata file, relative to `config.toml` |
| `auth_saml_entity_id` | SAML service provider entity ID; defaults to the metadata URL of each host |
| `auth_saml_subject_attribute` | SAML attribute that names the visitor; defaults to the NameID |
| `auth_smtp_addr` | SMTP server `host:port`; required when `auth = "email"` |
| `auth_smtp_username` | SMTP username for `auth = "email"`; set together with the password |
| `auth_smtp_password` | SMTP password for `auth = "email"` |
| `auth_smtp_from` | Fixed sender address of every login link; required when `auth = "email"` |
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
- Application auth cannot be combined with `tcp` or `udp`; `auth_allowed_wallets`, `auth_email_list`, `auth_identity_headers`, and the `auth_oidc_*`, `auth_saml_*` and `auth_smtp_*` fields require `auth`, `auth_email_list` requires `auth = "oidc"`, `"saml"` or `"email"`, `auth_allowed_wallets` and `auth_email_list` cannot both be set, `auth = "email"` takes only `auth_email_list`, the `auth_oidc_*` fields require `auth = "oidc"`, the `auth_saml_*` fields require `auth = "saml"`, and the `auth_smtp_*` fields require `auth = "email"`.
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

The agent restricts `config.toml` before it stores a credential in it. When the
tunnels it saves hold an OIDC client secret, an SMTP password, an inline
`identity_json` or an x402 facilitator token, it removes the group and other permissions from the
file on Linux and macOS (`0644` becomes `0600`; the owner's bits stay) and, if
it cannot, fails the change without writing anything. On Windows it checks the
file's ACL. This happens when the agent saves the file, through the dashboard or
the control API; a config you write by hand is not touched until then, so create
it with `0600` when it holds a secret.

The agent refuses non-loopback `control_addr` values. Use `127.0.0.1`,
`localhost`, or another loopback address.

Control endpoints:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/agent/status` | Bearer token or wallet session | Read agent and tunnel status |
| `POST` | `/agent/shutdown` | Bearer token | Ask the agent to stop |
| `POST` | `/agent/tunnels` | Bearer token | Add a tunnel |
| `PATCH` | `/agent/tunnels/{id}` | Bearer token | Update metadata, max active relays, or application sign-in |
| `DELETE` | `/agent/tunnels/{id}` | Bearer token | Delete a tunnel |
| `POST` | `/agent/tunnels/{id}/relays` | Bearer token | Connect a relay |
| `DELETE` | `/agent/tunnels/{id}/relays` | Bearer token | Disconnect a relay |

`POST /agent/tunnels` accepts the `auth`, `auth_allowed_wallets`, `auth_email_list`, `auth_identity_headers`, `auth_oidc_*`, `auth_saml_*`, and `auth_smtp_*` fields, with the meaning they have in `config.toml`. The agent does not write the settings that the request leaves out, such as `discovery` or `max_active_relays`, to `config.toml`. `GET /agent/status` reports their defaults.

`POST /agent/tunnels` accepts `serve`, a static site directory or HTML file with the meaning it has in `config.toml`. A tunnel with `serve` gets no default target, and `serve` cannot be combined with `target_addr` or `http_routes`. A relative `serve` path is resolved from the directory of `config.toml`, not from the caller's working directory, and saved as the resulting absolute path.

`PATCH /agent/tunnels/{id}` changes the fields it names (`max_active_relays`, `metadata`, `auth`, `auth_allowed_wallets`, `auth_email_list`, `auth_identity_headers`, `auth_oidc_issuer`, `auth_oidc_client_id`, `auth_oidc_client_secret`, `auth_saml_metadata_url`, `auth_saml_metadata_file`, `auth_saml_entity_id`, `auth_saml_subject_attribute`, `auth_smtp_addr`, `auth_smtp_username`, `auth_smtp_password`, `auth_smtp_from`) and leaves the others as they are. A field sent as `null` also stays as it is. The agent refuses an `auth_*` field that it does not know. Field names match without regard to case, and the agent refuses a request that sends one auth field twice, such as `auth` and `AUTH`. `"auth": ""` turns sign-in off and clears the other `auth_*` settings, so it is refused when the same request sets one of them. To change the provider, send the new `auth` with the fields that fit it and clear the ones that do not (for example empty `auth_oidc_issuer`, `auth_oidc_client_id` and `auth_oidc_client_secret` when leaving OIDC, the empty `auth_saml_*` fields when leaving SAML, or the empty `auth_smtp_*` fields when leaving email); a combination the validators refuse changes nothing. A tunnel cannot hold both lists, so send an empty `auth_allowed_wallets` or `auth_email_list` to clear the key that no longer fits, in the same request that sets the other. `auth_oidc_client_secret` and `auth_smtp_password` are write-only, and an empty value clears them. A username and a password are set together, so clear `auth_smtp_password` and `auth_smtp_username` in the same request. The resulting tunnel must pass the same validation as `config.toml`; if it does not, the request fails and neither the file nor the running tunnel changes. Changed sign-in settings restart that tunnel and no other, because the sign-in gate is built when the tunnel starts. It starts again from its saved settings: relays connected to it with `POST /agent/tunnels/{id}/relays` are not saved in `config.toml`, so it comes back without them. Metadata and `max_active_relays` update the running tunnel in place.

`GET /agent/status` reports each tunnel's `auth`, `auth_allowed_wallets`, `auth_email_list`, `auth_identity_headers`, `auth_oidc_issuer`, `auth_oidc_client_id`, `auth_saml_*`, `auth_smtp_addr`, `auth_smtp_username`, and `auth_smtp_from` fields, plus `auth_oidc_client_secret_set` and `auth_smtp_password_set`, which say whether a client secret or an SMTP password is configured; the secrets themselves are never returned. A wallet session, which can only read the status, sees no allow lists and no SMTP account: it gets the status without `auth_allowed_wallets`, `auth_email_list`, `auth_smtp_addr`, `auth_smtp_username`, `auth_smtp_from`, and `auth_smtp_password_set`, and the fixed message `smtp server check failed` replaces the SMTP check error. The list fields are also left out when a list is empty, so a wallet-session client cannot tell a hidden allowlist from an empty one. A running OIDC, SAML or email tunnel also reports the provider check it runs once when it starts: `auth_provider_checked` is true once the check has finished, and `auth_provider_error` says why the provider (its discovery document and keys, its SAML metadata, or its SMTP server and login) was not usable. Before SAML support, these two fields were named `auth_oidc_provider_checked` and `auth_oidc_provider_error`. A client that reads the old names sees no provider check until it reads the new ones. The check is not repeated: once the provider recovers, visitors can sign in again, but the error stays in the status until the tunnel restarts.

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
