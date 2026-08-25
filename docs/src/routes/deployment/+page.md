---
title: Deployment
description: Production deployment guide for a Portal relay server.
priority: P1
---

# Portal Relay Deployment Guide

Portal production deployment uses one image and one public HTTPS origin. The
Go binary owns TLS, SNI routing, relay APIs, tunnel ingress, and the embedded
React SPA. Operators can replace only the SPA files without adding a reverse
proxy or changing ownership of the Portal API paths.

## Production Topology

```text
Browser or tunnel client
  -> https://portal.example.com or https://*.portal.example.com
  -> Portal :443 SNI router
      -> root host: internal API listener
          -> /api/*, /sdk/*, /discovery*, /v1/sign
          -> embedded React SPA for /, /admin, and client routes
      -> registered wildcard host: tunnel ingress
```

The internal API listener defaults to `4017/tcp` and is not published by the
bundled Compose deployment. Root-host traffic reaches it through Portal's own
SNI router.

## Prerequisites

- A public Linux server with Docker and Docker Compose.
- A public hostname such as `portal.example.com`.
- A one-time NS delegation at the parent zone: `NS portal.example.com -> ns.portal.example.com` with a glue `A` record pointing at the relay public IP. See the [Configuration Reference](/configuration#embedded-dns) for the canonical embedded DNS details.
- Inbound `443/tcp`, `53/tcp` + `53/udp` for the embedded authoritative DNS, and `51820/udp` when the overlay is enabled.
- Certificates for the root and wildcard names are issued automatically via ACME DNS-01 against the embedded authoritative DNS.

## Configuration

Create `.env` next to `docker-compose.yml`:

```dotenv
PORTAL_URL=https://portal.example.com
ADMIN_TOKEN=replace-with-a-long-random-value
LANDING_PAGE_ENABLED=false

DISCOVERY=false
BOOTSTRAPS=

# Embedded authoritative DNS is the default provider and needs no API
# credentials once the NS delegation above is in place. External providers
# (cloudflare, gcloud, hetzner, njalla, route53, vultr) remain available by
# setting ACME_DNS_PROVIDER explicitly.
ACME_DNS_PROVIDER=
EMBEDDED_DNS_PORT=53
```

`LANDING_PAGE_ENABLED` supplies the initial value. Changes made from the admin
dashboard are stored in `IDENTITY_PATH/policy.json` and survive restarts.

## Custom Community Frontend

Portal serves the official embedded SPA when `PORTAL_FRONTEND_DIR` is empty.
To use a React, Vue, Svelte, Astro, or other static SPA, build it with client
routes falling back to `index.html`, then mount its output directory read-only:

```yaml
services:
  portal:
    environment:
      PORTAL_FRONTEND_DIR: /srv/portal/frontend
    volumes:
      - ./community-frontend/dist:/srv/portal/frontend:ro
```

The mounted directory must contain a regular `index.html`; Portal fails at
startup with a configuration error when it does not. Custom assets own `/` and
client-side routes, while `/api`, `/sdk`, `/discovery`, and `/v1` remain reserved
Portal paths. Community frontends can therefore use the stable JSON APIs
without owning TLS routing or running nginx.

Frameworks that require a live SSR server cannot be mounted as static files.
Run those applications separately and call the Portal API over HTTPS; the API
allows cross-origin requests. Static-export modes can use the mount directly.

To override ACME with a manually managed certificate, place these files in
`./.portal-certs`:

```text
fullchain.pem
privatekey.pem
tenant/fullchain.pem
tenant/privatekey.pem
```

The root certificate must cover the Portal hostname. The tenant certificate must
cover only the corresponding wildcard name and must use a different key. Managed
ACME, including the embedded DNS provider, creates and renews both pairs automatically.

## Deploy

```bash
mkdir -p ./.portal-certs
docker compose pull portal
docker compose up -d --force-recreate --remove-orphans portal
```

For a local source build:

```bash
docker compose up -d --build --force-recreate --remove-orphans portal
```

The Compose stack publishes:

| Port | Purpose |
|---|---|
| `443/tcp` | Portal HTTPS, SPA, APIs, and SNI tunnel ingress |
| `53/tcp` + `53/udp` | Embedded authoritative DNS for the delegated relay zone |
| `51820/udp` | Relay discovery overlay |
| configured lease range | Optional UDP and raw TCP leases |

Port `80/tcp` is not required. Operators who need HTTP-to-HTTPS redirects may
add a small external redirect service, but it must not terminate wildcard
tunnel TLS.

## Verify

```bash
curl -fsS https://portal.example.com/api/healthz
curl -fsS https://portal.example.com/sdk/domain
curl -I https://portal.example.com/
curl -I https://portal.example.com/admin
docker compose ps
```

Expected runtime services:

```text
portal
```

The `/admin` request must return the SPA entry rather than `404`. Registered
subdomains must continue to reach their tunnel targets through the same public
443 listener.

## Automated Updates

Production deployments should follow the v2 release track:

```text
ghcr.io/gosuda/portal:2
```

The bundled watcher tracks that image and recreates only the Portal service:

```bash
cp <repo>/docs/static/examples/auto-update/watch_and_deploy.sh ./watch_and_deploy.sh
chmod +x watch_and_deploy.sh
./watch_and_deploy.sh
```

## Migration From the Split Stack

1. Confirm `./.portal-certs` contains the Portal certificate and state.
2. Pull or build the new single Portal image.
3. Stop the old stack so it releases public port 443.
4. Start `portal` with `--remove-orphans` to remove the old edge and frontend
   containers.
5. Verify the SPA, relay APIs, and at least one wildcard tunnel.

The old edge configuration and its separate browser certificate are no longer
used. Portal owns the public certificate and performs only one TLS handshake
for root-host requests.

## Troubleshooting

### Port 443 Is Already Allocated

Stop the previous edge container or host service before starting Portal:

```bash
docker compose down --remove-orphans
docker compose up -d portal
```

### SPA Routes Return 404

When `PORTAL_FRONTEND_DIR` is empty, use an image built after the embedded
frontend migration. When it is set, confirm the mounted directory contains
`index.html` and all asset paths expected by that file. `/admin` and other
non-reserved client routes fall back to the selected SPA's `index.html`.

### Certificate Errors

Confirm `PORTAL_URL` matches the certificate root hostname and inspect the
certificate files under `IDENTITY_PATH`. With the embedded DNS provider,
confirm the delegation is visible (`dig @<relay public IP> portal.example.com NS`)
and that `53/tcp` + `53/udp` are reachable. With an external provider, verify
the DNS API token has permission to update the selected zone.

### API Port 4017

Do not publish or browse directly to 4017 in the bundled deployment. It is the
internal TLS API listener used by Portal's root-host SNI route.
