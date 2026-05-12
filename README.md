# Portal - The Trustless Relay Network for Localhost

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Portal Demo" src="./portal.gif" /></p>

<p align="center"><b>Expose local services to the public internet with zero trust in the relay operator.</b><br/>No port forwarding. No inbound firewall rules. No manual DNS setup. No surveillance.</p>

## Why Portal? The Trustless Advantage

Most tunneling services (ngrok, Cloudflare Tunnel) terminate your TLS connection at their edge. This means **they can read your plaintext traffic**. Portal is built on a fundamentally different model: **relays are blind by design**.

- **End-to-End Encryption with ECH** — Your HTTPS traffic stays encrypted through the relay, and ECH-capable clients avoid exposing the real hostname in plaintext SNI. Portal keeps TLS on your machine, so relay operators cannot read your web traffic or easily profile it by hostname.

- **Built-in MITM Detection** — Portal actively self-probes its own connection after real traffic begins. It compares TLS keying material exported on both the client and server sides. A mismatch is treated as suspected relay-side TLS termination and the relay is banned by default.

- **Self-Hostable, Fully Open Source** — Run your own relay with a single command. The relay is MIT-licensed with no enterprise tier, no feature gating, and no call-home. Your relay, your rules.

- **Anonymous Relay Network** — Because relays are trustless, you can connect to any public relay in the registry without compromising your privacy. Combine self-hosted relays with public relays in a pool — or chain them in a multi-hop route — to split trust across independent operators you choose.

- **Multi-Hop Relay Routing** — Chain multiple relays together (similar to Tor). No single relay knows both the origin and the destination of the traffic. Use `--multi-hop-depth 3` to select a three-hop route automatically.

- **No Accounts, No API Keys** — Authentication uses SIWE (Sign-In with Ethereum) with a locally generated secp256k1 key pair. No email, no registration, no vendor lock-in.

## Comparison

| | Portal | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| End-to-end tenant TLS | **Yes** | No | No | No |
| SNI hiding (ECH) | **Yes** | No | No | No |
| MITM self-probe | **Built-in** | No | No | No |
| Multi-hop routing | **Yes** | No | No | No |
| Multi-relay failover | **Yes** | Managed | Built-in | No |
| Self-hostable | **Yes** | Enterprise only | No | Yes |
| Custom domain | **Yes** | Paid plans | Yes | Yes |
| Raw TCP port routing | **Yes** | Paid plans | No | Yes |
| UDP routing | **Yes** | Yes | Yes | Yes |
| Open source | **MIT** | No | Client only | Apache 2.0 |
| Account required | **No** | Yes | Yes | No |

## Quick Start

### Expose a local service

**macOS / Linux:**

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

**Windows (PowerShell):**

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

Portal prints a public HTTPS URL for your local app instantly. More examples:

```bash
# Custom name and relay
portal expose 3000 --name myapp --relays https://portal.example.com --discovery=false

# Mount frontend and API behind one URL
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173

# Raw TCP port (Minecraft, databases, SSH)
portal expose localhost:25565 --name minecraft --tcp

# Three-hop route for maximum anonymity
portal expose 3000 --multi-hop-depth 3
```

### Run your own relay

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel && cp .env.example .env
docker compose up
```

For public deployment with DNS automation (ACME), TCP/UDP port ranges, and admin settings, see [Deployment](docs/src/routes/deployment/+page.md).

## How End-to-End Encryption Works

```text
Browser
  → Relay SNI router  (reads only routing token, forwards raw bytes)
  → Reverse session
  → Portal tunnel     (performs TLS handshake locally, derives session keys)
  → Local service
```

1. The relay accepts the incoming connection and reads only the TLS ClientHello for SNI-based routing.
2. It forwards the raw encrypted stream over the reverse session without terminating TLS.
3. The Portal tunnel on your side completes the TLS handshake locally. Session keys are derived on your machine.
4. For relay-hosted domains, the tunnel obtains certificate signatures via `/v1/sign`, using the relay only as a keyless signing oracle. The relay signs handshake digests but never receives session keys.
5. After the handshake, the relay continues forwarding ciphertext without access to plaintext.

When ECH is enabled, the relay also cannot see the actual tenant hostname. It routes by an opaque token derived from the tunnel identity, while the real SNI stays inside the ECH-protected ClientHello.

## How Multi-Hop Routing Works

```text
Browser
  → Entry relay  (sees only the opaque route hostname)
  → Middle relay (sees only the next-hop token)
  → Exit relay   (sees only the reverse session token)
  → Portal tunnel
  → Local service
```

Each relay in the chain knows only its immediate neighbors. No single relay holds the full path. Tenant TLS still terminates only on your side — no relay in the chain receives tenant TLS plaintext.

## Public Relay Registry

Portal's official public relay registry is:

```text
https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json
```

Tunnel clients include this registry by default. If you operate a public Portal relay, open a pull request to add your relay URL to `registry.json`.

## Documentation

- [CLI Reference](cmd/portal-tunnel/README.md)
- [Concepts](docs/src/routes/concepts/+page.md)
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

MIT License — see [LICENSE](LICENSE).
