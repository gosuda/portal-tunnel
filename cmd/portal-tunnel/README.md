# Portal CLI

`cmd/portal-tunnel` builds the `portal` CLI. It exposes local services through
Portal relays without inbound firewall rules, port forwarding, or manual DNS
setup.

The relay owns transport, lease registration, routing, and relay policy. The
tunnel process owns local proxy behavior, routed HTTP policy, x402 route
payments, and tenant TLS termination for the default HTTPS stream path.

## Quick Start

Install from GitHub release assets:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

If a relay publishes its own installer:

```bash
curl -sSL https://portal.example.com/api/install.sh | bash
portal expose 3000 --relays https://portal.example.com --discovery=false
```

Run the multi-architecture image (`linux/amd64` and `linux/arm64`) with Compose
from this repository:

```bash
cd cmd/portal-tunnel
mkdir -p identity
# Linux only: Docker Desktop on macOS and Windows maps host ownership for you.
if [ "$(uname)" = Linux ]; then sudo chown -R 65532:65532 identity; fi
PORTAL_TUNNEL_TARGET=host.docker.internal:3000 \
PORTAL_TUNNEL_NAME=my-app \
docker compose up -d
docker compose logs -f portal-tunnel
```

Compose uses `ghcr.io/gosuda/portal-tunnel:latest` by default. Run `docker
compose pull` to refresh it, use `docker compose up -d --build` to build from
the current checkout, or set `PORTAL_TUNNEL_IMAGE` to select another published
tag. The host directory `./identity` persists the tunnel identity at
`/identity/identity.json`. The image runs as the distroless `nonroot` user
(UID/GID `65532`), so on Linux the host directory must be writable by that user.
Set `PORTAL_TUNNEL_IDENTITY_DIR` to use a different host directory.

### Agent Dashboard TUI

The Compose service also supports the interactive agent dashboard. Seed a new
agent config with its state directory inside the identity mount, then start the
agent in the foreground:

```bash
mkdir -p identity
CONFIG='[agent]
state_dir = "/identity"'
# On Linux the mount is owned by uid 65532, so seed it with sudo and hand the
# whole directory back. Docker Desktop on macOS and Windows maps ownership.
if [ "$(uname)" = Linux ]; then
  printf '%s\n' "$CONFIG" | sudo tee identity/config.toml >/dev/null
  sudo chown -R 65532:65532 identity
else
  printf '%s\n' "$CONFIG" > identity/config.toml
fi
docker compose run --rm portal-tunnel \
  agent run --foreground --config /identity/config.toml
```

The dashboard appears in the current terminal. Use **Add Tunnel** to create the
first tunnel; its configuration and identities are saved under `./identity`.
Press `Ctrl+C` to stop the foreground agent.

## Modes

Default HTTPS stream for most local web apps:

```text
portal expose 3000 --name myapp
```

Static site when you want to publish a local folder or a single HTML file
without running a server. Pass a directory (served with `index.html`) or an HTML
file (its folder is served with that file as the SPA/CSR entry). Unknown paths
fall back to the entry file, and paths escaping the folder are refused:

```text
portal expose --serve ./site --name my-app
portal expose --serve ./site/main.html --name my-app
```

Routed HTTP when one public URL should mount multiple local HTTP upstreams:

```text
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Paid routed HTTP with Sui USDC x402:

```text
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...
```

Routed HTTP serves `/x402/client.js` and `/x402/prepare` on the tunnel origin
for the Sui wallet flow. Casper clients instead consume the protected route's
402 requirements, sign with an external Casper x402 SDK, and retry with
`PAYMENT-SIGNATURE` or `X-PAYMENT`; Portal settles it through the configured
Casper facilitator before proxying the request.
The hosted CSPR.cloud facilitator requires `CSPR_CLOUD_API_KEY`, which Portal
sends as its server-side authorization token. A custom unauthenticated
facilitator does not require the token.

Raw TCP and UDP:

```text
portal expose localhost:25565 --name minecraft --tcp
portal expose localhost:8080 --udp --udp-addr localhost:19132 --name game
```

## Commands

```text
portal expose [flags] <target>
portal expose [flags] --http-route "PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT]" [...]
portal list [flags]
portal agent run [flags]
portal agent dashboard [flags]
portal agent stop [flags]
portal agent restart [flags]
portal update
portal version
```

Common `portal expose` flags:

```text
--name               Public hostname prefix; auto-generated when omitted
--relays             Additional relay API URLs, comma-separated
--discovery          Include registry relays and relay discovery expansion
--max-active-relays  Maximum auto-selected single-hop relays; multi-hop uses every eligible relay as an entry
--multi-hop          Ordered multi-hop relay API URLs, comma-separated
--multi-hop-depth    Automatically create this-depth multi-hop routes for every eligible entry relay
--ban-mitm           Ban relay when the MITM self-probe detects termination
--identity-path      Identity JSON file path; created automatically when missing
--identity-json      Identity JSON payload; overrides --identity-path when set
--description        Service description metadata
--tags               Service tags metadata, comma-separated
--thumbnail          Service thumbnail URL metadata
--thumbnail-from-target  Use the target's og:image when --thumbnail is empty
--owner              Service owner metadata
--hide               Hide service from relay listing screens
--serve              Serve a local static site: a directory (served with index.html) or an HTML file (folder served with that file as SPA/CSR entry)
--http-route         HTTP route mapping in PATH=UPSTREAM [METHOD[,METHOD...]:PAYMENT_AMOUNT] form
--x402-pay-to        Payment recipient address for this tunnel
--x402-testnet       Use Sui testnet when --x402-network is omitted
--x402-network       Optional Sui or Casper CAIP-2 network
--x402-asset         wCSPR CEP-18 contract hash required by Casper
--x402-endpoint      Optional Sui RPC or Casper facilitator endpoint; repeatable
--x402-facilitator-token  Casper facilitator authorization token; defaults to CSPR_CLOUD_API_KEY
--tcp                Request a dedicated raw TCP port on the relay
--udp                Enable public UDP relay
--udp-addr           Local UDP target
--metrics-addr       Optional host:port for Prometheus /metrics
```

## Agent

Use the agent for durable multi-tunnel operation from one config file:

```text
portal agent run
portal agent dashboard
portal agent stop
portal agent restart
```

The dashboard can edit basic tunnel settings, relays, and multi-hop routes. Add
Tunnel opens a small form for name, target or HTTP routes, x402 payment settings,
relays, discovery, and max active relays. After creation, routed HTTP paths,
route-level x402 amounts, payment network, and discovery mode are read-only in
the Settings pane. Edit `http_routes`, `x402_pay_to`, `x402_testnet`,
`x402_network`, `x402_asset`, `x402_endpoints`, `x402_facilitator_token`, or `discovery` in TOML, then
restart the agent or tunnel to change them.

## Constraints

- A positional `<target>` cannot be combined with `--http-route`.
- `--serve` cannot be combined with a positional `<target>`, `--http-route`,
  `--udp`, or `--tcp`. The `--serve` entry file must exist. Path traversal
  (`..`) is refused, but a symlink inside the folder that points outside it is
  still followed, so only serve folders you trust.
- `--http-route` cannot be combined with `--udp`.
- Route payment amounts such as `0.01` are part of `--http-route` and require
  `--x402-pay-to`. Sui is the default; Casper additionally requires
  `--x402-network casper:...` and the wCSPR contract in `--x402-asset`.
  The default CSPR.cloud facilitator also requires `CSPR_CLOUD_API_KEY`.
- `--multi-hop` cannot be combined with `--multi-hop-depth`.
- Multi-hop currently supports only the default SNI TLS stream transport.
- `--tcp` and `--udp` require matching relay transport support.

## More Docs

- [CLI Reference](../../docs/src/routes/cli-reference/+page.md)
- [Concepts](../../docs/src/routes/concepts/+page.md)
- [Configuration Reference](../../docs/src/routes/configuration/+page.md)
- [Portal Agent](../../docs/src/routes/portal-agent/+page.md)
- [Self Hosting](../../docs/src/routes/self-hosting/+page.md)
- [Wallet and ENS](../../docs/src/routes/wallet-and-ens/+page.md)
