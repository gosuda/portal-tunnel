---
title: Self-Hosting
description: Run your own Portal relay for private tunneling.
---

# Self-Hosting Guide

This guide is for developers who want their own relay for a single project or team — not a platform operator managing relay infrastructure for many users. If you need production-grade deployment with managed TLS, ACME automation, or multi-tenant relay infrastructure, see the [Deployment Guide](/deployment) instead.

You should have a relay running and accepting tunnel connections in about 10 minutes.

## Prerequisites

- Docker installed on your server
- A Linux server with a static public IP
- A domain name you control (e.g. `relay.example.com`)
- Inbound ports open on your server:
  - `443/tcp` — SNI router (tunnel traffic)
  - `4017/tcp` — Admin/API port (tunnel registration)

## Quick Start

Run the relay with a single Docker command:

```bash
mkdir -p ./relay-data
# Put fullchain.pem and privatekey.pem in ./relay-data first, or configure ACME below.
docker run -d \
  --name portal-relay \
  --restart unless-stopped \
  -p 443:443 \
  -p 4017:4017 \
  -e PORTAL_URL=https://relay.example.com:4017 \
  -e IDENTITY_PATH=/portal-certs \
  -v $(pwd)/relay-data:/portal-certs \
  ghcr.io/gosuda/portal:latest
```

Replace `relay.example.com` with your domain. The admin secret is generated on first start and stored in `IDENTITY_PATH/identity.json`.

## Docker Compose Setup

For a more maintainable setup, use Docker Compose:

```yaml
# compose.yml
services:
  relay:
    image: ghcr.io/gosuda/portal:latest
    restart: unless-stopped
    ports:
      - "443:443"
      - "4017:4017"
    environment:
      PORTAL_URL: https://relay.example.com:4017
      API_PORT: "4017"
      SNI_PORT: "443"
      IDENTITY_PATH: /portal-certs
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
| `PORTAL_URL` | `https://localhost:4017` | Public base URL of your relay. Tunnels use this to register. |
| `API_PORT` | `4017` | Admin/API server port. |
| `SNI_PORT` | `443` | TCP SNI router port for tunnel traffic. |
| `IDENTITY_PATH` | `./.portal-certs` | Relay state directory containing `identity.json`, `admin_settings.json`, and TLS materials. |

## Connecting Your Tunnel

Point `portal-tunnel` at your relay with the `--relays` flag:

```bash
portal expose --relays https://relay.example.com:4017 --discovery=false localhost:3000
```

The `--relays` flag accepts a comma-separated list of relay API URLs. If you omit the scheme, `https` is assumed.

To avoid typing `--relays` every time, use a shell alias:

```bash
alias portal-relay='portal expose --relays https://relay.example.com:4017 --discovery=false'
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
  ACME_DNS_PROVIDER: cloudflare   # or: gcloud, route53
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

Stop the conflicting service or change `SNI_PORT` and update your firewall rules accordingly.

**DNS not resolving**

Verify your wildcard record is live before connecting a tunnel:

```bash
dig +short test.relay.example.com
```

If nothing returns, check your DNS provider dashboard and allow more time for propagation.

**Firewall blocking connections**

Ensure both ports are open in your cloud provider's security group or firewall:

```bash
# UFW example
sudo ufw allow 443/tcp
sudo ufw allow 4017/tcp
```

**Certificate errors**

If you see TLS errors on the client side, confirm your certificate files are present in `IDENTITY_PATH` and that `fullchain.pem` includes the full chain (leaf + intermediates). If using ACME, check the relay logs for DNS provider authentication errors:

```bash
docker compose logs relay --tail 50
```
