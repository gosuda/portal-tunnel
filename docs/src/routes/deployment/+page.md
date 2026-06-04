---
title: Deployment
description: Production deployment guide for Portal relay servers.
priority: P1
---

<div class="not-prose mb-8 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300">
  <strong>Advanced Documentation</strong> - This page covers production relay deployment for operators.
</div>

# Portal Relay Deployment Guide

Portal supports two deployment profiles:

- API-only relay: one `portal` image exposes relay API paths and tunnel ingress
  directly. This is documented in [Self-Hosting](/self-hosting).
- Full Portal edge: `portal-nginx`, `portal`, `portal-frontend`, and `portal-api`
  provide one browser-facing HTTPS origin with dashboard, presentation API, and
  wildcard tunnel routing. When an existing public nginx already owns the
  domain, place the Portal edge nginx behind it and have the outer nginx
  passthrough Portal SNI traffic to the Portal edge.

This guide covers the full Portal edge profile and is the source of truth for
how the split relay, frontend, and presentation API are expected to be deployed
together.

## 1. Production Topology

The production deployment has five roles when Portal is mounted under a
subdomain of an existing nginx deployment:

| Role | Service or image | Publicly exposed | Owns |
|---|---|---|---|
| Existing public edge | your nginx | yes, `443/tcp` | SNI selection for Portal versus existing services |
| Portal edge | `portal-nginx`, `nginx:stable-alpine` | loopback only | Portal root-host TLS termination, path routing, wildcard SNI passthrough |
| Relay | `portal`, `ghcr.io/gosuda/portal` | no direct public API port | Relay API, wallet auth, policy enforcement, tunnel ingress |
| Static frontend | `portal-frontend`, `ghcr.io/gosuda/portal-frontend` | no direct public port | SPA assets |
| Presentation API | `portal-api`, `ghcr.io/gosuda/portal-api` | no direct public port | Frontend-owned state, policy composition, service status, thumbnails |

Traffic should flow through one public HTTPS origin:

```text
Browser
  -> https://portal.example.com
  -> existing public nginx TCP passthrough
  -> portal-nginx Portal edge
      -> portal-frontend for SPA routes and assets
      -> portal for /sdk/*, /discovery*, /v1/sign, and /api/* relay paths
      -> portal-api for /ui/* presentation API paths

Tunnel clients and public app visitors
  -> https://*.portal.example.com
  -> existing public nginx TCP passthrough
  -> portal-nginx TCP passthrough
  -> portal SNI listener
```

### Public Routing

| Public request | nginx behavior | Upstream |
|---|---|---|
| `portal.example.com/`, `/admin`, SPA assets | Existing nginx TCP-passthrough, then Portal edge TLS termination and HTTP proxy | `portal-frontend:8080` |
| `/sdk/*`, `/discovery*`, `/v1/sign` | Existing nginx TCP-passthrough, then Portal edge TLS termination and HTTP proxy | `portal:4017` over HTTPS |
| `/api/*` | Existing nginx TCP-passthrough, then Portal edge TLS termination and HTTP proxy | `portal:4017` over HTTPS |
| `/ui/*` | Existing nginx TCP-passthrough, then Portal edge TLS termination and HTTP proxy | `portal-api:8081` |
| `*.portal.example.com` | Raw TCP passthrough through both nginx layers | `portal` SNI listener |

The root relay host needs HTTP path routing, so it is not TCP-passthrough. Wildcard app hosts need TCP passthrough, so nginx must not terminate TLS for them.

### Migration From Embedded Frontend

Older deployments could run only `ghcr.io/gosuda/portal` because the relay served frontend assets. Current production deployment separates that into:

- `portal` for relay API and tunnel ingress
- `portal-frontend` for static SPA assets
- `portal-api` for frontend-owned dynamic behavior
- `portal-nginx` as the Portal TLS edge

Operators upgrading from the embedded frontend must deploy all three Portal
images and route them through `portal-nginx`. `PORTAL_URL` remains the
browser-facing HTTPS origin, for example `https://portal.example.com`; do not
set it to `localhost` or an internal Docker hostname for a public relay.

When Portal is mounted under a subdomain of a larger nginx deployment, keep
Portal's routing isolated behind `portal-nginx`. The outer nginx should use
`ssl_preread` and send both `portal.example.com` and `*.portal.example.com` to
the loopback Portal edge port without TLS termination. `portal-nginx` then
terminates TLS only for `portal.example.com` and passes wildcard tunnel hosts
through to the relay SNI listener.

### Security Boundary

To keep the same practical security level as the embedded frontend deployment:

- Public users reach the dashboard only through `https://portal.example.com`.
- The existing public nginx does not expose `portal:4017`, `portal-frontend:8080`, or `portal-api:8081` directly.
- The existing public nginx forwards Portal root and wildcard SNI traffic to `portal-nginx` without TLS termination.
- `portal-nginx` terminates TLS only for the root host and reverse-proxies `/sdk/*`, `/discovery*`, `/v1/sign`, and `/api/*` to the relay API upstream, while `/ui/*` presentation paths go to `portal-api`.
- Wildcard app hosts are TCP-passthrough through `portal-nginx` to the relay SNI listener.
- `portal-nginx` and `portal` share the same Portal certificate and private key.

This example intentionally keeps the external nginx template focused on service
selection. Portal-specific path routing stays inside `portal-nginx`, and raw
wildcard tunnel hosts are never TLS-terminated by the external nginx.

## 2. Prerequisites

You need:

- A public domain, for example `portal.example.com`.
- A public Linux server with a static public IPv4.
- Docker and Docker Compose.
- DNS `A` records for the relay host and wildcard host:

```text
portal.example.com   -> <server-ip>
*.portal.example.com -> <server-ip>
```

If you use Cloudflare, keep these records `DNS only`. Proxied records break the raw wildcard TCP passthrough path.

Open only the public ports that match the topology:

| Port | Required | Purpose |
|---|---|---|
| `80/tcp` | optional | HTTP to HTTPS redirect in your external nginx |
| `443/tcp` | yes | Existing public nginx SNI selection for Portal and non-Portal services |
| `WIREGUARD_PORT/udp` | when `DISCOVERY=true` | Relay discovery WireGuard transport |
| `SNI_PORT/udp` | when UDP transport is enabled | QUIC tunnel ingress |
| `MIN_PORT-MAX_PORT/udp` | when UDP lease transport is enabled | Public UDP lease ports |
| `MIN_PORT-MAX_PORT/tcp` | when raw TCP lease transport is enabled | Public raw TCP lease ports |

Keep these ports private or loopback-only in the recommended topology:

| Port | Owner |
|---|---|
| `PORTAL_EDGE_PORT/tcp` | `portal-nginx` loopback passthrough upstream for your external nginx |
| `4017/tcp` | `portal` relay API |
| `8080/tcp` | `portal-frontend` static server |
| `8081/tcp` | `portal-api` presentation API |

Certificate files are also split by owner:

| Certificate | Default path in the example | Used by |
|---|---|---|
| Portal root and wildcard certificate | `./.portal-certs/fullchain.pem`, `./.portal-certs/privatekey.pem` | `portal-nginx` and `portal` |
| Existing app certificates | managed by your external nginx template | existing non-Portal services |

Portal-managed ACME can manage the Portal certificate and relay DNS records.
Your existing nginx template remains responsible for certificates for
non-Portal services.

## 3. Deploy the Recommended Stack

Start from the subdomain multi-service example:

```bash
mkdir -p portal-deploy
cd portal-deploy

cp <repo>/docs/static/examples/nginx-proxy-multi-service/docker-compose.yaml ./docker-compose.yaml
cp <repo>/docs/static/examples/nginx-proxy-multi-service/.env.example ./.env
cp <repo>/nginx.conf.template ./nginx.conf.template
```

Replace `portal.example.com` in `.env`, and configure your existing public nginx
template to passthrough both `portal.example.com` and `*.portal.example.com` to
`127.0.0.1:${PORTAL_EDGE_PORT:-9443}` without TLS termination.

### Configure `.env`

Minimal production baseline:

```bash
PORTAL_URL=https://portal.example.com
BOOTSTRAPS=
DISCOVERY=true
IDENTITY_PATH=/portal-certs
PORTAL_EDGE_PORT=9443

API_PORT=4017
SNI_PORT=443
WIREGUARD_PORT=51820
MIN_PORT=0
MAX_PORT=0
UDP_ENABLED=false
TCP_ENABLED=false

ACME_DNS_PROVIDER=
ENS_GASLESS_ENABLED=false

TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=

LANDING_PAGE_ENABLED=false
```

`PORTAL_EDGE_PORT` is the host loopback port your existing nginx should use as
the Portal passthrough upstream. `API_PORT` defaults to `4017`; if you change
it, update the relay `proxy_pass` targets in `nginx.conf.template` before
mounting it. Keep `SNI_PORT=443` because this is the public SNI port advertised
to tunnel clients.

If the relay joins public discovery, set `BOOTSTRAPS` to at least one reachable relay URL and keep `WIREGUARD_PORT/udp` open.

The relay identity wallet can always sign in through admin auth. Set `ADMIN_WALLETS` only when you need additional admin wallets.

Leave `TRUSTED_PROXY_CIDRS` empty for the default private and loopback proxy ranges. Set it only when you need a stricter proxy source allowlist.

### Prepare Certificates and State

Create the state directories:

```bash
mkdir -p ./.portal-certs/frontend-state
sudo chown 65532:65532 ./.portal-certs
chmod 755 ./.portal-certs
```

In manual certificate mode, place the Portal root and wildcard certificate here
before startup:

```text
./.portal-certs/fullchain.pem
./.portal-certs/privatekey.pem
```

`portal-nginx` and the `portal` container must share this same pair. Tunnel TLS
uses the relay keyless signer, so if nginx presents one certificate while
`portal` signs with a different private key, browsers will fail the wildcard app
handshake with protocol errors or TLS `bad signature` diagnostics.

When `ACME_DNS_PROVIDER` is configured, Portal can create and renew this
certificate under `IDENTITY_PATH`.

### Start and Verify

Start the stack:

```bash
docker compose up -d
```

Verify the public edge:

```bash
curl -I https://portal.example.com
docker compose ps
```

Expected service names in the recommended stack:

- `portal-nginx`
- `portal`
- `portal-frontend`
- `portal-api`

If `https://portal.example.com` loads the dashboard and tunnel app hosts under `*.portal.example.com` reach the relay, the topology is correct.

## 4. Certificate and DNS Automation

Choose one certificate and DNS mode for the relay.

| Mode | `ACME_DNS_PROVIDER` | Relay cert source | DNS automation |
|---|---|---|---|
| Manual certificate | empty | `IDENTITY_PATH/fullchain.pem` and `IDENTITY_PATH/privatekey.pem` | none |
| Manual certificate plus gasless DNS | DNSSEC-capable provider | manual files | ENS TXT and DNSSEC automation |
| Managed ACME | supported provider | Portal-managed ACME DNS-01 | root/wildcard A records, ECH HTTPS records, relay cert renewal |

Supported provider values:

| Provider | Required environment | ENS gasless support |
|---|---|---|
| `cloudflare` | `CLOUDFLARE_TOKEN` | yes |
| `gcloud` | Google ADC, optionally `GCP_PROJECT_ID`, `GCP_MANAGED_ZONE`, `GOOGLE_APPLICATION_CREDENTIALS` | yes |
| `route53` | AWS credentials or instance role, optionally `AWS_HOSTED_ZONE_ID` | yes, needs an active KSK or `AWS_DNSSEC_KMS_KEY_ARN` |
| `vultr` | `VULTR_API_KEY` | yes |
| `hetzner` | `HETZNER_API_TOKEN` | no |
| `njalla` | `NJALLA_TOKEN` | no |

For `gcloud` with a service account file under Docker Compose, mount the file and point `GOOGLE_APPLICATION_CREDENTIALS` at the in-container path:

```yaml
services:
  portal:
    environment:
      GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/gcp-dns.json
    volumes:
      - ./.portal-certs:/portal-certs
      - ./gcp-dns.json:/run/secrets/gcp-dns.json:ro
```

### ENS Gasless Automation

ENS gasless DNS import is optional and not required for normal relay operation.

Enable it only when you need ENS-aware clients to resolve Portal domains through gasless DNSSEC import:

```bash
ACME_DNS_PROVIDER=cloudflare
CLOUDFLARE_TOKEN=cf_xxxxxxxxxxxxxxxxx
ENS_GASLESS_ENABLED=true
```

Operational notes:

- ENS gasless requires `ACME_DNS_PROVIDER`.
- Portal writes `ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 <address>` TXT records.
- The base domain uses the relay identity address; lease hostnames use each lease identity address.
- Provider-side DNSSEC automation is not the same as registrar-side DS publication.
- If the provider returns a `DS` record or reports DNSSEC as pending, publish the DS record at your registrar and wait for parent-zone propagation.
- Keep `ENS_GASLESS_ENABLED=false` unless you intentionally use this feature.

Verification checklist:

```bash
dig +short DS portal.example.com
dig +short TXT portal.example.com
```

Provider DNSSEC should be active, and the TXT response should include the `ENS1 ...` value.

## 5. Optional UDP and Raw TCP Transport

UDP transport and raw TCP lease transport are disabled by default.

Open these ports in your cloud security group or host firewall only when the matching feature is enabled:

- `WIREGUARD_PORT/udp` when discovery is enabled.
- `SNI_PORT/udp` when UDP tunnel ingress is enabled.
- `MIN_PORT-MAX_PORT/udp` when UDP lease transport is enabled.
- `MIN_PORT-MAX_PORT/tcp` when raw TCP lease transport is enabled.

Example with `MIN_PORT=40000`, `MAX_PORT=40009`, and `SNI_PORT=443`:

```bash
sudo ufw allow 51820/udp
sudo ufw allow 443/udp
sudo ufw allow 40000:40009/udp
sudo ufw allow 40000:40009/tcp
```

Configure the shared lease range in `.env`:

```bash
MIN_PORT=40000
MAX_PORT=40009
UDP_ENABLED=true
TCP_ENABLED=true
```

When using bridge networking, publish the same range in `docker-compose.yaml`:

```yaml
ports:
  - "${WIREGUARD_PORT:-51820}:${WIREGUARD_PORT:-51820}/udp"
  - "${SNI_PORT:-443}:${SNI_PORT:-443}/udp"
  - "${MIN_PORT:-40000}-${MAX_PORT:-40009}:${MIN_PORT:-40000}-${MAX_PORT:-40009}/udp"
  - "${MIN_PORT:-40000}-${MAX_PORT:-40009}:${MIN_PORT:-40000}-${MAX_PORT:-40009}"
```

UDP and raw TCP use the same numeric range independently, so the same number can be allocated once for UDP and once for TCP.

After startup, enable UDP or raw TCP policy in the admin UI and set any lease limits you want to enforce.

For better QUIC performance on Linux:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

Persist those values in `/etc/sysctl.conf` or a file under `/etc/sysctl.d/` if needed.

## 6. Frontend Presentation API

`portal-api` is a small TypeScript service owned by the frontend deployment. It keeps frontend-specific behavior out of the Go relay.

It owns:

- `/ui/state` composition with frontend-owned fields.
- `/ui/policy/*` composition, while relay-enforced policy changes are still forwarded to `portal`.
- `/ui/service/status`, derived from relay state for quick-start UI checks.
- `/ui/thumbnail/<hostname>`, when optional screenshot generation is enabled.
- The landing-page flag persisted at `PORTAL_FRONTEND_STATE_PATH`; the bundled Compose files store it under `./.portal-certs/frontend-state/state.json`.

The Go relay remains the owner of authentication, policy enforcement, lease state, tunnel ingress, install scripts, discovery, and x402 facilitator paths.

### Thumbnail Screenshots

Generated thumbnails are optional and disabled by default. Without this feature, apps without a custom thumbnail simply use the default card background.

To enable generated thumbnails:

1. Uncomment the `headless-shell` service in `docker-compose.yaml`.
2. Add `headless-shell` to `portal-api.depends_on`.
3. Set `HEADLESS_SHELL_URL=ws://headless-shell:9222`.
4. Restart with `docker compose up -d`.

Expected log when a thumbnail is captured:

```text
thumbnail captured hostname=myapp.portal.example.com size=36209
```

Disable the feature by removing `HEADLESS_SHELL_URL` and stopping the `headless-shell` container.

## 7. Auto-Update

Auto-update should follow a published release tag, not `latest`. The `latest`
image tag tracks default-branch image builds, so using it can update production
on a `main` merge before the GitHub Release and tunnel binaries are published.

The bundled Compose examples use the v2 release track directly. Auto-update must
pull all production images from that same release track:

- `ghcr.io/gosuda/portal:2`
- `ghcr.io/gosuda/portal-frontend:2`
- `ghcr.io/gosuda/portal-api:2`

To update the Portal stack:

```bash
docker compose pull portal portal-frontend portal-api
docker compose up -d portal-nginx portal portal-frontend portal-api
```

If your existing public nginx template changed, reload that external nginx
through your normal deployment process. The Portal compose example does not own
the external nginx lifecycle.

## 8. Troubleshooting

### `4017` Shows Only API

That is expected. `4017/tcp` is the relay API, not the dashboard. Use `https://portal.example.com` through nginx for the production UI.

### Frontend Logs Show Binary TLS Bytes and `400`

Logs like `"\x16\x03\x01..." 400` mean a client sent HTTPS to the plain HTTP
`portal-frontend:8080` listener. Do not expose `8080` publicly. Route public
Portal traffic through `portal-nginx`.

### Relay Logs Show `tls: unknown certificate`

This usually means a browser or proxy hit the relay API certificate directly, or
an upstream proxy tried to verify the relay's internal certificate. Public
browsers should reach `portal-nginx`, while `portal-nginx` proxies to the relay
API over internal HTTPS with upstream verification disabled.

### Root Host Works but Wildcard Apps Fail

Check both nginx layers. The external nginx must passthrough both
`portal.example.com` and `*.portal.example.com` to the loopback
`PORTAL_EDGE_PORT`. Only `portal-nginx` should split root-host HTTP routing from
wildcard SNI passthrough. Do not terminate TLS for wildcard app hosts in the
external nginx.

### Wildcard Apps Show `ERR_SSL_PROTOCOL_ERROR`

If `openssl s_client` reports `tls_process_cert_verify:bad signature`, nginx is
presenting a certificate whose private key is not the one used by the Portal
keyless signer. Make `portal-nginx` and `portal` use the same
`./.portal-certs/fullchain.pem` and `./.portal-certs/privatekey.pem` pair, then
restart both services and reconnect the tunnel clients.

### Discovery Announce Is Rejected as Local-Only

Public discovery rejects `PORTAL_URL` hosts such as `localhost`, `127.0.0.1`, `::1`, or other local-only names. Set `PORTAL_URL` to a publicly reachable HTTPS hostname.

### Docker DNS Resolution Fails

If logs show `discover bootstraps failed`, `sync dns records`, or `lookup <host> on 127.0.0.11:53: write: operation not permitted`, Docker is usually using the wrong host resolver config.

On Linux hosts with `systemd-resolved`, point `/etc/resolv.conf` at the upstream resolver list and restart Docker:

```bash
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart docker
docker compose up -d
```

Verify from the container:

```bash
docker run --rm --network container:portal busybox nslookup api4.ipify.org
```

### Ports Are Blocked

Confirm the required public ports are open:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 51820/udp
sudo ufw status
```

Only add UDP and raw TCP lease ranges when those transports are enabled.
