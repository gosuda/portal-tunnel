<p align="center">
  <img src="./logo.png" alt="Portal" width="280" />
</p>

# Portal

[![CI](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/gosuda/portal-tunnel)](https://github.com/gosuda/portal-tunnel/releases/latest)

Expose local services through public or self-hosted relays. No hosted account,
inbound firewall rule, or port forwarding is required on the tunnel client.
Portal supports HTTPS, routed HTTP, raw TCP, UDP, and opt-in static caching.

## Install and expose

macOS or Linux:

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

Windows PowerShell:

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

The command prints the public URL. It creates or loads `identity.json`; use
`--identity-path` to keep a stable identity across working directories.

```bash
# Use only a selected relay.
portal expose 3000 --relays https://portal.example.com --discovery=false

# Serve a static site, with SPA fallback.
portal expose --serve ./dist

# Mount multiple local HTTP services behind one URL.
portal expose --http-route /api=http://127.0.0.1:3001 --http-route /=http://127.0.0.1:5173

# Request a public raw TCP port.
portal expose localhost:25565 --tcp
```

See the [CLI reference](docs/src/routes/cli-reference/+page.md) for UDP, overlay
transport, x402 paid routes, flags, and constraints.

## Trust boundaries

Ordinary HTTPS tunnels terminate tenant TLS in the local tunnel process. The
relay routes encrypted traffic by SNI and provides transcript-bound keyless
signatures. `--ban-mitm` bans a relay when the self-probe detects a TLS exporter
mismatch; the probe samples connections, not all traffic.

`--serve ./dist --cache` explicitly trusts selected relays with the static files
and browser TLS termination, including origin fallback on that connection.
Use explicit `--relays` with `--discovery=false` to limit which relays receive
those files. Raw TCP and UDP need application-level encryption for confidentiality.
See the [security model](docs/src/routes/security-model/+page.md).

## Persistent tunnels

```bash
portal agent run --config config.toml
portal agent dashboard --config config.toml
```

The agent runs as a local OS service. See the [agent guide](docs/src/routes/portal-agent/+page.md)
for configuration, foreground mode, Docker Compose, and shutdown.

The [portal-deploy plugin](plugins/portal-deploy/README.md) exposes apps from
coding agents and checks the public endpoint. Install its shared skill with:

```bash
npx skills add gosuda/portal-tunnel --skill portal-expose
```

## Run a relay

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel
cp .env.example .env
```

Configure the public domain, DNS, certificate storage, and admin token before
starting `docker compose up -d`. Follow the [deployment guide](docs/src/routes/deployment/+page.md).

Tunnel clients use [registry.json](registry.json) by default. To list a public
relay, submit a pull request adding its URL there.

## Reference

| Topic | Documentation |
|---|---|
| First tunnel and Docker Compose | [Getting started](docs/src/routes/getting-started/+page.md) |
| Runtime configuration | [Configuration](docs/src/routes/configuration/+page.md) |
| Wire APIs | [API reference](docs/src/routes/api-reference/+page.md) |
| Transport and ownership | [Architecture](docs/src/routes/architecture/+page.md) |
| Identities and DNS | [Wallet and ENS](docs/src/routes/wallet-and-ens/+page.md) |

Contribution policy is in [CONTRIBUTING.md](CONTRIBUTING.md); implementation
rules are in [AGENTS.md](AGENTS.md). Licensed under [MIT](LICENSE).
