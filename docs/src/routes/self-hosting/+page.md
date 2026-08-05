---
title: Self-Hosting
description: Run your own Portal relay for private tunneling.
---

# Self-Hosting Guide

This guide is for developers who want their own relay for a single project or
team. The `portal` image serves the dashboard, relay APIs, and tunnel ingress
from one public HTTPS origin.

You should have a relay running and accepting tunnel connections in about 10 minutes.

## Prerequisites

- Docker installed on your server
- A Linux server with a static public IP
- A domain name you control (e.g. `relay.example.com`)
- Inbound `443/tcp` open for the dashboard, relay APIs, and SNI tunnel traffic

## Quick Start

Run the relay with a single Docker command:

```bash
mkdir -p ./relay-data
# Put fullchain.pem and privatekey.pem in ./relay-data first, or configure ACME below.
docker run -d \
  --name portal-relay \
  --restart unless-stopped \
  -p 443:443 \
  -e PORTAL_URL=https://relay.example.com \
  -e IDENTITY_PATH=/portal-certs \
  -e ADMIN_TOKEN="$(openssl rand -hex 32)" \
  -v $(pwd)/relay-data:/portal-certs \
  ghcr.io/gosuda/portal:2
```

Replace `relay.example.com` with your domain. Keep the generated
`ADMIN_TOKEN`; it is required for relay admin and policy access.

## Docker Compose Setup

For a more maintainable setup, use Docker Compose:

```yaml
# compose.yml
services:
  relay:
    image: ghcr.io/gosuda/portal:2
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      PORTAL_URL: https://relay.example.com
      API_PORT: "4017"
      SNI_PORT: "443"
      IDENTITY_PATH: /portal-certs
      ADMIN_TOKEN: ${ADMIN_TOKEN}
    volumes:
      - ./relay-data:/portal-certs
```

Start it:

```bash
docker compose up -d
```

### Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORTAL_URL` | `https://localhost` | Public HTTPS origin of the relay and embedded dashboard. |
| `API_PORT` | `4017` | Internal Admin/API server port. |
| `SNI_PORT` | `443` | TCP SNI router port for tunnel traffic. |
| `IDENTITY_PATH` | `./.portal-certs` | Relay state directory containing `identity.json`, `policy.json`, and TLS materials. |
| `ADMIN_TOKEN` | | Bearer token source for relay admin and policy APIs. |
| `LANDING_PAGE_ENABLED` | `false` | Initial dashboard landing-page visibility; admin changes persist in `policy.json`. |

## Optional: Enable Relay-Owned Sui x402 Facilitator

To reserve relay-side x402 support for future control-plane resources, enable
the relay-owned facilitator. This is intended for relay-owned charges such as
tunnel registration, lease renewal, raw TCP/UDP port allocation, or premium
capacity if an operator decides to require them. Payments use Sui mainnet by
default; set `X402_TESTNET=true` for Sui testnet.

```yaml
environment:
  X402_ENABLED: "true"
  X402_TESTNET: "false"
  X402_PAY_TO: "0x..."
```

This serves `/api/x402/supported`, `/api/x402/verify`, and `/api/x402/settle`.
Portal payments intentionally support only Sui mainnet/testnet USDC through the
gasless stablecoin address-balance flow.

Tunnel paid routes do not use these relay settings. Route-level payment
enforcement is configured separately by the tunnel with
`portal expose --x402-pay-to` and optional `--x402-testnet`; relay
`X402_PAY_TO` and `X402_TESTNET` are reserved for relay-owned control-plane
resources.

## Connecting Your Tunnel

Point `portal-tunnel` at your relay with the `--relays` flag:

```bash
portal expose --relays https://relay.example.com --discovery=false localhost:3000
```

The `--relays` flag accepts a comma-separated list of relay API URLs. If you omit the scheme, `https` is assumed.

To avoid typing `--relays` every time, use a shell alias:

```bash
alias portal-relay='portal expose --relays https://relay.example.com --discovery=false'
portal-relay localhost:3000
```

## DNS Configuration

Tunnels are assigned subdomains under your relay domain (e.g. `abc123.relay.example.com`). You need a wildcard DNS record pointing to your server:

| Type | Name | Value |
|---|---|---|
| `A` | `*.relay.example.com` | `<your server IP>` |
| `A` | `relay.example.com` | `<your server IP>` |

DNS propagation typically takes a few minutes but can take up to 48 hours depending on your provider.

## Optional: TLS with ACME

By default the relay expects you to place `fullchain.pem` and `privatekey.pem` in the `IDENTITY_PATH` directory (`.portal-certs` by default). For automatic certificate management via DNS-01 challenges, set `ACME_DNS_PROVIDER`:

```yaml
environment:
  ACME_DNS_PROVIDER: cloudflare   # or: gcloud, hetzner, njalla, route53, vultr
  CLOUDFLARE_TOKEN: <your-token>
```

See the [Deployment Guide](/deployment) for full ACME configuration options, credential setup per provider, and managed DNS automation.

## Optional: Enable TCP/UDP Tunneling

To relay raw TCP or UDP traffic (game servers, databases, etc.), enable the transports and set a port range:

```yaml
environment:
  TCP_ENABLED: "true"
  UDP_ENABLED: "true"
  MIN_PORT: "10000"
  MAX_PORT: "10100"
ports:
  - "10000-10100:10000-10100/tcp"
  - "10000-10100:10000-10100/udp"
```

See [TCP/UDP Tunneling](/tcp-udp-tunneling) for usage details.

## Troubleshooting

**Port already in use**

Port `443` is commonly taken by another process. Check what's listening:

```bash
sudo ss -tlnp | grep ':443'
```

Stop or reconfigure the conflicting service. The bundled public deployment
requires TCP `443` because Portal publishes standard HTTPS tunnel URLs.

**DNS not resolving**

Verify your wildcard record is live before connecting a tunnel:

```bash
dig +short test.relay.example.com
```

If nothing returns, check your DNS provider dashboard and allow more time for propagation.

**Firewall blocking connections**

Ensure the public HTTPS port is open in your cloud provider's security group or firewall:

```bash
# UFW example
sudo ufw allow 443/tcp
```

**Certificate errors**

If you see TLS errors on the client side, confirm your certificate files are present in `IDENTITY_PATH` and that `fullchain.pem` includes the full chain (leaf + intermediates). If using ACME, check the relay logs for DNS provider authentication errors:

```bash
docker compose logs relay --tail 50
```
