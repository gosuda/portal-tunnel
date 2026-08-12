# Webhole — Self-Hostable Relay Tunnel for Localhost

[![CI](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/gosuda/portal-tunnel)](https://github.com/gosuda/portal-tunnel/releases/latest)
[![License](https://img.shields.io/github/license/gosuda/portal-tunnel)](./LICENSE)
[![awesome-tunneling](https://img.shields.io/badge/awesome--tunneling-listed-blue)](https://github.com/anderspitman/awesome-tunneling)

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Webhole Demo" src="./portal.gif" /></p>

<p align="center"><b>Expose local services through self-hosted or public relays.</b><br/>No port forwarding. No inbound firewall rules. No manual DNS setup. No accounts.</p>

## Why Webhole?

Webhole is a local tunnel runtime and relay network for publishing services to the agentic web.
It publishes local apps, APIs, tools, and agents through self-hosted or public relays,
keeps routing and x402 payment policy in the tunnel process, and avoids requiring a hosted vendor account.

- **Self-Hostable, Fully Open Source** - Run your own relay with a single
  command. The relay is MIT-licensed with no enterprise tier, no feature gating,
  and no call-home. Your relay, your rules.

- **Anonymous Relay Network** - Connect to public relays without a hosted
  account or central operator. Combine self-hosted relays with public relays in
  a pool to split trust across independent operators you choose.

- **End-to-End Tenant TLS And ECH** - Because relays are trustless, Webhole
  terminates tenant TLS at the user's endpoint instead of the relay. Webhole also
  provides ECH to avoid exposing the real hostname in plaintext SNI.

- **Built-in MITM Detection** - Webhole actively self-probes its own connection
  after real traffic begins. It compares TLS keying material exported on both
  sides and treats a mismatch as suspected relay-side TLS termination.

- **Multi-Hop Relay Routing** - Chain multiple relays together so no single
  relay knows both the origin and the destination. Use `--multi-hop-depth 3` to
  select a three-hop route automatically.

- **No Accounts, No API Keys** - Authentication uses SIWE-compatible signing
  with a locally generated secp256k1 key pair. No email, no registration, no
  vendor lock-in.

- **Built-in x402 Payments** - Routed HTTP paths can require Sui gasless
  USDC or Casper wCSPR x402 payment before proxying. Browser apps can import
  `/x402/client.js`, and native clients can call `/x402/prepare` directly and
  send `X-PAYMENT`.

## Comparison

| | Webhole | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| Public localhost URL | **Yes** | Yes | Yes | Yes |
| Self-hostable | **Yes** | Enterprise only | No | Yes |
| Open source | **MIT** | No | Client only | Apache 2.0 |
| Custom domain | **Yes** | Paid plans | Yes | Yes |
| End-to-end tenant TLS | **Yes** | No | No | No |
| SNI hiding (ECH) | **Yes** | No | No | No |
| MITM self-probe | **Built-in** | No | No | No |
| Multi-relay failover | **Yes** | Managed | Built-in | No |
| Multi-hop routing | **Yes** | No | No | No |
| Account required | **No** | Yes | Yes | No |
| Native x402 payments | **Yes** | No | No | No |

## Quick Start

### Expose a local service

**macOS / Linux:**

```bash
curl -fsSL https://github.com/gosuda/webhole/releases/latest/download/install.sh | bash
portal expose 3000
```

**Windows (PowerShell):**

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/webhole/releases/latest/download/install.ps1 | iex
portal expose 3000
```

Webhole prints a public HTTPS URL for your local app instantly. More examples:

```bash
# Custom name and relay
portal expose 3000 --name myapp --relays https://portal.example.com --discovery=false

# Mount frontend and API behind one URL
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173

# Require Sui USDC x402 payment before proxying a route
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...

# Raw TCP port (Minecraft, databases, SSH)
portal expose localhost:25565 --name minecraft --tcp

# Three-hop route for maximum anonymity
portal expose 3000 --multi-hop-depth 3
```

See [CLI Reference](cmd/portal-tunnel/README.md) for the full route syntax and
[API Reference](docs/src/routes/api-reference/+page.md#payments) for the x402
helper endpoints.

### Keep tunnels running with Webhole Agent

Use `portal agent run` when tunnels should keep running outside your terminal.
It runs as a local OS service, keeps every tunnel in one TOML config alive, and
provides a dashboard for relay and multi-hop management.

```bash
portal agent run --config config.toml
portal agent dashboard --config config.toml
portal agent restart
portal agent stop

# Foreground mode skips OS service installation.
portal agent run --config config.toml --foreground
```

See [Webhole Agent](docs/src/routes/portal-agent/+page.md) for the config format.

### Run your own relay

```bash
git clone https://github.com/gosuda/webhole
cd webhole && cp .env.example .env
docker compose up
```

For public deployment with DNS automation (ACME), TCP/UDP port ranges, and relay
policy, see [Deployment](docs/src/routes/deployment/+page.md).

## How End-to-End Encryption Works

```text
Browser
  -> Relay SNI router  (reads only routing token, forwards raw bytes)
  -> Reverse session
  -> Webhole tunnel    (performs TLS handshake locally, derives session keys)
  -> Local service
```

1. The relay accepts the incoming connection and reads only the TLS ClientHello
   for SNI-based routing.
2. It forwards the raw encrypted stream over the reverse session without
   terminating TLS.
3. The Webhole tunnel on your side completes the TLS handshake locally. Session
   keys are derived on your machine.
4. For relay-hosted domains, the tunnel obtains certificate signatures via
   `/v1/sign`, using the relay only as a keyless signing oracle. The relay signs
   handshake digests but never receives session keys.
5. After the handshake, the relay continues forwarding ciphertext without access
   to plaintext.

When ECH is enabled, the relay also cannot see the actual tenant hostname. It
routes by an opaque token derived from the tunnel identity, while the real SNI
stays inside the ECH-protected ClientHello.

## How Multi-Hop Routing Works

```text
Browser
  -> Entry relay  (sees only the opaque route hostname)
  -> Middle relay (sees only the next-hop token)
  -> Exit relay   (sees only the reverse session token)
  -> Webhole tunnel
  -> Local service
```

Each relay in the chain knows only its immediate neighbors. No single relay
holds the full path. Tenant TLS still terminates only on your side, so no relay
in the chain receives tenant TLS plaintext.

## Public Relay Registry

Webhole's official public relay registry is:

```text
https://raw.githubusercontent.com/gosuda/webhole/main/registry.json
```

Tunnel clients include this registry by default. If you operate a public Webhole
relay, open a pull request to add your relay URL to `registry.json`.

## Documentation

- [CLI Reference](cmd/portal-tunnel/README.md)
- [Concepts](docs/src/routes/concepts/+page.md)
- [Webhole Agent](docs/src/routes/portal-agent/+page.md)
- [Wallet and ENS](docs/src/routes/wallet-and-ens/+page.md)
- [Security Model](docs/src/routes/security-model/+page.md)
- [Architecture](docs/src/routes/architecture/+page.md)
- [Deployment](docs/src/routes/deployment/+page.md)
- [Configuration Reference](docs/src/routes/configuration/+page.md)

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Make the change with focused tests or docs.
4. Open a pull request.

## License

MIT License - see [LICENSE](LICENSE).
