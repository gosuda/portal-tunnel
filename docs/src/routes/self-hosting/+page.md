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
- Inbound `53/tcp` + `53/udp` open for the embedded authoritative DNS

## Quick Start

Run the relay with a single Docker command:

```bash
mkdir -p ./relay-data
# Optional manual TLS: place the API pair in ./relay-data and a distinct
# wildcard-only pair in ./relay-data/tenant. Managed ACME creates both.
docker run -d \
  --name portal-relay \
  --restart unless-stopped \
  --cap-add NET_BIND_SERVICE \
  -p 443:443 \
  -p 53:53/tcp \
  -p 53:53/udp \
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
    # Binding the default embedded DNS port 53 as a nonroot container.
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "443:443"
      - "53:53/tcp"
      - "53:53/udp"
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
| `EMBEDDED_DNS_PORT` | `53` | Embedded authoritative DNS listen port; requires `53/tcp` + `53/udp` and `CAP_NET_BIND_SERVICE` in containers. |

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

> The [Configuration Reference](/configuration#embedded-dns) is the canonical source for embedded DNS settings. This section summarizes the delegation step only.

The relay serves DNS for its own subdomains from the embedded authoritative
server (`relay.example.com` and every name under it, including tunnel
hostnames). Delegate the zone to the relay once from your existing DNS
management UI:

| Type | Name | Value |
|---|---|---|
| `NS` | `relay.example.com` | `ns.relay.example.com` |
| `A` | `ns.relay.example.com` | `<your server IP>` (glue) |
No wildcard record is needed: the relay synthesizes answers for every tunnel
hostname. The nameserver name is fixed to `ns.<your relay domain>`; publish the
matching glue `A` record at the parent zone as shown above.

## TLS with ACME

Certificates are issued automatically via ACME DNS-01 against the embedded
authoritative DNS server — no DNS provider credentials are required once the
delegation above is in place. To use an external DNS provider instead, set
`ACME_DNS_PROVIDER`:

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

Query the relay's authoritative server directly first, then through a public
resolver:

```bash
dig +short @<your server IP> test.relay.example.com
dig +short test.relay.example.com
```

If the direct query works but the public one does not, the NS delegation at
the parent zone is missing or not yet propagated. If both fail, confirm the
relay is running and `53/tcp` + `53/udp` are open.

**Firewall blocking connections**

Ensure the public HTTPS and DNS ports are open in your cloud provider's
security group or firewall:

```bash
# UFW example
sudo ufw allow 443/tcp
sudo ufw allow 53/tcp
sudo ufw allow 53/udp
```

**Certificate errors**

If you see TLS errors on the client side, confirm your certificate files are present in `IDENTITY_PATH` and that `fullchain.pem` includes the full chain (leaf + intermediates). If using ACME, check the relay logs for DNS provider authentication errors:

```bash
docker compose logs relay --tail 50
```
