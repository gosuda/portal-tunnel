# PORTAL - Public Open Relay To Access Localhost

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Portal Demo" src="./portal.gif" /></p>

<p align="center">Expose your local application to the public internet - no port forwarding, no NAT, no DNS setup.<br />Portal is a trustless relay network where relays cannot access your traffic. Connect to any relay or chain several for better anonymity.</p><br />

## Features

- **Public HTTPS for localhost**: NAT-friendly publishing via TCP passthrough
- **End-to-end TLS**: TLS terminates on the client, relays can`t access plaintext or session keys
- **Relay discovery pools**: Choose multiple discovered relays as a flexible connection pool
- **Multi-hop relay routing**: Improve anonymity by splitting the traffic path across multiple relays
- **Self-hosted relays**: Run your own relay or connect to public relays
- **No login, no API keys**: Authenticate ownership using SIWE, with ENS-based identity support
- **Raw TCP/UDP routing**: Native TCP reverse sessions, optional UDP, and dedicated TCP ports for non-TLS services

## Comparison

| | Portal | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| End-to-end encryption | **Yes** | Optional | No | No |
| TLS termination | Client-side | Edge (default) | Edge (always) | Server-side |
| MITM detection | **Built-in** | No | No | No |
| Self-hostable | **Yes** | Enterprise only | No | Yes |
| multi-relay failover | **Yes** | Managed | Built-in multi-DC | No |
| multi-hop routing | **Yes** | No | No | No |
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

`https://raw.githubusercontent.com/gosuda/portal-tunnel/main/config.toml`

Portal tunnel clients can include this registry by default, and the relay UI also reads from the same path to show the official relay list.

If you operate a public Portal relay, open a Pull Request to add your relay URL to `config.toml`. Keeping the registry updated makes public relays easier for the community to discover.

## How Portal Provides End-to-End Encryption

Portal is designed so that tenant TLS terminates on your side rather than at the relay. In the normal data path, the relay forwards encrypted traffic without access to tenant TLS plaintext.

1. The relay accepts the public connection and reads only the TLS ClientHello required for SNI-based routing.
2. It forwards the tenant connection as raw encrypted bytes over the reverse session without terminating tenant TLS.
3. The Portal client on your side acts as the TLS server and completes the tenant handshake locally.
4. For relay-hosted domains, the Portal client obtains certificate signatures via `/v1/sign`, using the relay only as a keyless signing oracle.
5. Session keys are derived entirely on your side. The relay provides certificate signatures only and does not receive tenant traffic secrets.
6. After the handshake, the relay continues forwarding ciphertext without needing tenant TLS plaintext to keep routing traffic.

Portal also checks that the relay is preserving TLS passthrough. The Portal client connects to its own public endpoint and compares TLS exporter values observed on both client-controlled ends. If they differ, `portal expose` rejects the relay by default.

## How Portal Provides Multi-Hop Relay Routing

Portal can route a tunnel through an ordered chain of relays. This splits responsibility and visibility across multiple nodes instead of relying on a single relay.

1. The client selects multiple relays and forms a relay chain.
2. Public traffic enters through the ingress relay, which only knows the hostname it serves.
3. Each relay forwards to the next hop without learning the whole route.
4. The last relay reaches your Portal client through the reverse session.
5. Tenant TLS still terminates only on your side. No relay receives tenant TLS plaintext.

This improves anonymity by splitting routing knowledge across independent relays while preserving Portal's end-to-end encrypted traffic model.

For CLI usage, see [cmd/portal-tunnel/README.md](cmd/portal-tunnel/README.md).

## Contributing

We welcome contributions from the community!

1. Fork the repository
2. Create a feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE)
