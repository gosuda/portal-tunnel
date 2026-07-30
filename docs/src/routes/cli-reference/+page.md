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
curl -sSL https://portal.example.com/api/install.sh | bash
```

The installer downloads the `portal` binary and adds it to your `PATH`. It does
not create a config file.

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
portal expose [flags] --http-route "PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]" [...]
```

The payment suffix is optional; omit it for free routes.

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
| `--max-active-relays` | int | `3` | Maximum auto-selected single-hop relays to keep connected; multi-hop uses every eligible relay as an entry; explicit relays are always included |
| `--multi-hop` | string | | Ordered multi-hop relay API URLs, comma-separated |
| `--multi-hop-depth` | int | `0` | Automatically create this-depth multi-hop routes for every eligible entry relay; `0` or `1` disables multi-hop |
| `--ban-mitm` | bool | `false` | Ban relay when the MITM self-probe detects TLS termination |
| `--identity-path` | string | `identity.json` | Identity JSON file path; created automatically when missing |
| `--identity-json` | string | | Identity JSON payload; overrides `--identity-path` contents and is persisted there when both are set |
| `--name` | string | auto | Public hostname prefix, one DNS label |
| `--description` | string | | Service description metadata |
| `--tags` | string | | Service tags metadata, comma-separated |
| `--thumbnail` | string | | Service thumbnail URL metadata |
| `--owner` | string | | Service owner metadata |
| `--hide` | bool | `false` | Hide service from relay listing screens |
| `--x402-pay-to` | string | | Sui USDC payment recipient address for this tunnel |
| `--x402-testnet` | bool | `false` | Use Sui testnet for tunnel x402 payments; default is Sui mainnet |
| `--http-route` | string | | HTTP route mapping in `PATH=UPSTREAM [METHOD[,METHOD...]:USDC_AMOUNT]` form; repeatable; route amounts require `--x402-pay-to` |
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
- Route payment amounts are part of `--http-route` and require a tunnel-owned
  `--x402-pay-to`.
- Tunnel paid routes use Sui mainnet by default; add `--x402-testnet` for Sui
  testnet. This is independent of relay-owned x402 facilitator settings.

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

Ask Portal to create three-hop routes for every eligible entry relay:

```bash
portal expose 3000 --multi-hop-depth 3
```

Ban relays on MITM probe detection:

```bash
portal expose 3000 --ban-mitm
```

Publish a paid HTTP route:

```bash
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...
```

The optional method list limits which methods require payment; without it, every
method on that route prefix is paid.

The routed HTTP handler also serves `/x402/client.js` and `/x402/prepare` on the
public tunnel origin. Frontends served by one of the routes can use the shared
browser-only Sui wallet client for an in-page payment flow:

```js
import { getSuiWallets, x402Fetch } from '/x402/client.js';

const [wallet] = getSuiWallets();
if (!wallet) {
  throw new Error('Install a Sui wallet');
}

const [account] = await wallet.accounts();
if (!account) {
  throw new Error('Connect a Sui account');
}

const response = await x402Fetch('/paid/photo', { method: 'GET' }, {
  wallet,
  account,
  onEvent: (event) => console.log(event.type, event.message),
});
```

`x402Fetch()` is a convenience wrapper: it asks `/x402/prepare` for the payment
transaction, asks the wallet to sign it, then retries the protected request with
an `X-PAYMENT` header. `onEvent` receives structured progress events; the older
`onStatus(message)` callback is still accepted for simple UIs. Routed HTTP
payments use Sui mainnet by default; pass `--x402-testnet` when exposing the
tunnel and use `network: 'sui:testnet'` in wallet clients that need an explicit
network. For mainnet, omit `network` or pass `sui:mainnet`.

Native clients should not load `/x402/client.js`. Call `POST /x402/prepare` with
`{ "sender": "...", "method": "GET", "path": "/paid/photo" }`, execute
`prepareTransaction.transaction` first when present, sign
`paymentTransaction.transaction`, and send the resulting x402 payload as the
`X-PAYMENT` header on the protected request:

```js
const payload = {
  x402Version: prepared.x402Version,
  payload: {
    signature,
    transaction: prepared.paymentTransaction.transaction,
  },
  accepted: prepared.paymentRequirements,
  resource: prepared.resource,
};
const header = base64(JSON.stringify(payload));
```

The frontend integration is optional. Requests without a valid `X-PAYMENT`
header still receive x402 payment-required responses from the tunnel.

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
| `portal agent dashboard` | Open the local TUI for tunnels, relays, multi-hop routes, and settings |
| `portal agent stop` | Gracefully stop the agent and disable or stop the OS service |
| `portal agent restart` | Stop the current agent if present, install or update the service, and start it again |

The local control API binds only to loopback and uses a token in the agent state
directory. See [Portal Agent](/portal-agent) for the workflow and
[Configuration Reference](/configuration#configtoml) for the `config.toml`
format.

Agent flags:

| Command | Flag | Default | Description |
|---------|------|---------|-------------|
| `portal agent run` | `--config` | platform default | Agent TOML config path |
| `portal agent run` | `--foreground` | `false` | Run in the current process without installing the OS service |
| `portal agent run` | `--service` | `false` | Internal service entrypoint used by the installed OS service |
| `portal agent dashboard` | `--config` | platform default | Config path used for display and state-dir discovery |
| `portal agent dashboard` | `--state-dir` | config/default | Agent state directory to attach to |
| `portal agent stop` | `--config` | platform default | Config path used to resolve state dir and service name |
| `portal agent stop` | `--state-dir` | config/default | Agent state directory to stop |
| `portal agent restart` | `--config` | platform default | Config path used to reinstall and restart the service |

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

- `portal expose` and `portal list` check the latest published GitHub Release in
  the background. A `main` merge or branch artifact is not offered to installed
  clients until the release is created with matching binary and checksum assets.
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
- [Portal Agent](/portal-agent): run durable multi-tunnel services
- [Wallet and ENS](/wallet-and-ens): understand admin tokens, wallet auth, and ENS gasless DNS
- [Concepts](/concepts): understand the relay and transport model
- [TCP and UDP Tunneling](/tcp-udp-tunneling): raw TCP and UDP setup
- [Deployment](/deployment): run your own relay server
