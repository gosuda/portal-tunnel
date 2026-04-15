# PORTAL - Public Open Relay To Access Localhost

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Portal Demo" src="./portal.gif" /></p>

<p align="center">Expose your local application to the public internet - no port forwarding, no NAT, no DNS setup.<br />Portal is a trustless relay network where relays cannot access your traffic. Connect to any relay or run your own.</p><br />

## Features

- **Public HTTPS for localhost**: NAT-friendly publishing via TCP passthrough (no port forwarding)
- **End-to-end TLS**: TLS terminates on your side with built-in MITM detection, so relays cannot access plaintext
- **One-command setup**: Start relays and tunnels with minimal setup
- **Self-hosted relays**: Connect to public relays or run your own
- **Relay discovery and pools**: Use discovered relays as a pool, with multi-relay access and failover
- **No login, no API keys**: Authenticate ownership using SIWE, with ENS-based identity support
- **Raw TCP/UDP + TCP port routing**: Native TCP reverse sessions, optional UDP, and dedicated TCP ports for non-TLS services
- **Auto-generated thumbnails**: Optional headless screenshot sidecar generates dashboard card previews for tunnel apps

## Comparison

| | Portal | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| End-to-end encryption | **Yes** | Optional | No | No |
| TLS termination | Client-side | Edge (default) | Edge (always) | Server-side |
| MITM detection | **Built-in** | No | No | No |
| Self-hostable | **Yes** | Enterprise only | No | Yes |
| Multi-relay failover | **Yes** | Managed | Built-in multi-DC | No |
| Custom domain | **Yes** | Paid plans | Yes | Yes |
| Transport | Raw TCP / UDP | HTTP/S, TCP, TLS | HTTP/S, TCP, UDP | HTTP/S, TCP, UDP |
| Non-TLS TCP port routing | **Yes** | Paid plans | No | Yes |
| Open source | **MIT** | No | Client only (Apache 2.0) | Apache 2.0 |
| Account required | **No** (SIWE) | Yes | Yes | No |

## Quick Start

### Expose your local app:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

Then access your app via a public HTTPS URL.
For install details, see [cmd/portal-tunnel/README.md](cmd/portal-tunnel/README.md).

### Run your own relay

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel && cp .env.example .env
docker compose up
```

For deployment to a public domain, see [Deployment](docs/src/routes/deployment/+page.md).

### Run native app (Advanced)

See [portal-toys](https://github.com/gosuda/portal-toys) for more examples.

## Architecture

See [Architecture](docs/src/routes/architecture/+page.md).

## Examples

| Example | Description |
|---------|-------------|
| [nginx reverse proxy](docs/static/examples/nginx-proxy/) | Deploy Portal behind nginx with L4 SNI routing and TLS termination |
| [nginx + multi-service](docs/static/examples/nginx-proxy-multi-service/) | Run Portal alongside other web services behind a single nginx instance |

## Public Relay Registry

Portal's official public relay registry is:

`https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json`

Portal tunnel clients can include this registry by default, and the relay UI also reads from the same path to show the official relay list.

If you operate a public Portal relay, open a Pull Request to add your relay URL to `registry.json`. Keeping the registry updated makes public relays easier for the community to discover.

## How Portal Provides End-to-End Encryption

Portal is designed so that tenant TLS terminates on your side rather than at the relay. In the normal data path, the relay forwards encrypted traffic without access to tenant TLS plaintext.

1. The relay accepts the public connection and reads only the TLS ClientHello required for SNI-based routing.
2. It forwards the tenant connection as raw encrypted bytes over the reverse session without terminating tenant TLS.
3. The Portal client on your side acts as the TLS server and completes the tenant handshake locally.
4. For relay-hosted domains, the Portal client obtains certificate signatures via `/v1/sign`, using the relay only as a keyless signing oracle.
5. Session keys are derived entirely on your side. The relay provides certificate signatures only and does not receive tenant traffic secrets.
6. After the handshake, the relay continues forwarding ciphertext without needing tenant TLS plaintext to keep routing traffic.

Portal also checks that the relay is preserving TLS passthrough. The Portal client connects to its own public endpoint and compares TLS exporter values observed on both client-controlled ends. If they differ, `portal expose` rejects the relay by default.

## Contributing

We welcome contributions from the community!

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE)
