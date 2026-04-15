---
title: Deployment
description: Production deployment guide for Portal relay servers.
priority: P1
---

<div class="not-prose mb-8 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300">
  <strong>Advanced Documentation</strong> — This page covers production relay deployment for operators.
</div>

# Portal Relay Deployment Guide

This guide covers the production steps for running Portal Relay on a public domain.

## 1. Prerequisites

You need:

- A public domain, for example `example.com`
- A public Linux server with a static public IPv4
- Docker and Docker Compose
- Optional for managed ACME DNS-01 automation or Portal-managed ENS TXT sync: a supported DNS provider account for `cloudflare`, `gcloud`, or `route53`
- Open inbound ports:
  - `443/tcp`
  - `4017/tcp`
  - optional for UDP transport:
    - `SNI_PORT/udp`
    - `MIN_PORT-MAX_PORT/udp` (see section 5)
  - optional for raw TCP port transport:
    - `MIN_PORT-MAX_PORT/tcp` (see section 5)

## 2. Certificate and DNS Mode

Choose one of these modes:

- Manual certificate mode
  - Leave `ACME_DNS_PROVIDER` empty.
  - Place `fullchain.pem` and `privatekey.pem` in `IDENTITY_PATH`.
  - Portal uses the files as-is and does not modify DNS or renew the certificate.
- Manual certificate + gasless mode
  - Place `fullchain.pem` and `privatekey.pem` in `IDENTITY_PATH`.
  - Set `ACME_DNS_PROVIDER`.
  - Portal keeps the manual certificate files, skips ACME certificate issuance, and still uses the provider for DNSSEC + ENS TXT automation.
- Managed ACME mode
  - Set `ACME_DNS_PROVIDER` to `cloudflare`, `gcloud`, or `route53`.
  - Portal manages root/wildcard A records and certificate renewal.
  - If ENS gasless is enabled, Portal also manages DNSSEC.

If you only need a relay and do not need Portal-managed DNS or automatic renewal, manual certificate mode is the simplest option.

## 3. Managed ACME Provider Setup

### 3.1 Choose ACME DNS provider

Set `ACME_DNS_PROVIDER` to one of:

- `cloudflare`
- `gcloud`
- `route53`

### 3.2 Cloudflare setup

#### Add domain to Cloudflare

1. Cloudflare Dashboard -> `Websites` -> `Add a Site`
2. Enter your domain, for example `example.com`
3. Complete onboarding and apply Cloudflare nameservers at your registrar
4. Wait until zone status is `Active`

#### Create DNS records

If `PORTAL_URL=https://example.com`, create:

- `example.com -> <server-ip>`
- `*.example.com -> <server-ip>`

If you deploy on a non-apex host such as `PORTAL_URL=https://portal.example.com:8443`, create:

- `portal.example.com -> <server-ip>`
- `*.portal.example.com -> <server-ip>`

Set both records as:

- Type: `A`
- Proxy status: `DNS only`

#### Create Cloudflare API token

Cloudflare Dashboard -> `My Profile` -> `API Tokens` -> `Create Token`

Required permissions:

- `Zone:Read`
- `DNS:Edit`
- optional when `ENS_GASLESS_ENABLED=true` and `ACME_DNS_PROVIDER=cloudflare`:
  - `Zone Settings:Edit`

Scope:

- Limit the token to the target zone

Save the token for `CLOUDFLARE_TOKEN`.

### 3.3 Route53 setup

Create or select a public hosted zone that covers your relay host.

Provide Route53 write access through either:

- static AWS credentials, or
- ambient AWS credentials such as an instance role

Static credential environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- optional `AWS_SESSION_TOKEN`
- `AWS_REGION`, for example `us-east-1`

Optional:

- `AWS_HOSTED_ZONE_ID`

Equivalent relay flags:

- `--aws-access-key-id`
- `--aws-secret-access-key`
- `--aws-session-token`
- `--aws-region`
- `--aws-hosted-zone-id`

When `ENS_GASLESS_ENABLED=true` and `ACME_DNS_PROVIDER=route53` and the hosted zone does not already have an active Route53 key-signing key (KSK), also provide:

- `AWS_DNSSEC_KMS_KEY_ARN`

### 3.4 Google Cloud DNS setup

Create or select a public Cloud DNS managed zone that covers your relay host.

Portal uses standard Google Application Default Credentials (ADC) for both Cloud DNS API access and lego DNS-01. Examples:

- `GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcp-dns.json` with a mounted service account JSON file
- an attached service account or workload identity on GCE, GKE, or Cloud Run

Optional environment variables:

- `GCP_PROJECT_ID`
- `GCP_MANAGED_ZONE`
- `GOOGLE_APPLICATION_CREDENTIALS`

Equivalent relay flags:

- `--gcp-project-id`
- `--gcp-managed-zone`

Notes:

- `GCP_PROJECT_ID` is optional when ADC or GCE metadata already exposes the project id.
- `GCP_MANAGED_ZONE` is optional, but useful when the credentials can edit a specific managed zone without permission to list all zones.
- `GOOGLE_APPLICATION_CREDENTIALS` should point to the in-container path when you run Portal in Docker with a mounted service account JSON file.
- Portal only targets public Cloud DNS managed zones.

### 3.5 Optional ENS Gasless Automation

Portal can optionally enable ENS gasless DNS import for the base domain and lease hostnames.

- This is not required for normal Portal deployment.
- Enable it only when you specifically need ENS gasless DNS import.
- ENS gasless automation requires `ACME_DNS_PROVIDER`.
- Portal uses that provider for both DNSSEC automation and ENS TXT create/delete.
- If valid manual certificate files already exist in `IDENTITY_PATH`, Portal keeps using them and does not force ACME certificate issuance just because `ACME_DNS_PROVIDER` is set.
- Cloudflare can enable zone signing directly, but some registrars still require publishing the returned DS record.
- Google Cloud DNS can enable zone signing directly, but the registrar may still require publishing the returned DS record.
- Route53 requires a compatible KMS key ARN when no active KSK already exists, and the registrar may still require the DS record.
- New lease hostnames such as `app.portal.example.com` are published automatically when they register and are cleaned up on unregister or expiry.
- ENS gasless import still depends on DNSSEC being valid for the domain.
- By default Portal writes `ENS1 0x238A8F792dFA6033814B18618aD4100654aeef01 <address>`.
- The address is derived automatically from the relay identity for the base domain and from each lease identity for lease hostnames.
- This enables offchain gasless DNSSEC usage in ENS-aware clients. It does not perform an onchain ENS claim transaction.
- Portal can automate provider-side DNS changes, but registrar-side DS publication is not always automatable. Expect a manual registrar step unless your registrar publishes DS records automatically.
- Keep `ENS_GASLESS_ENABLED=false` unless you intend to use ENS gasless DNS import.

Typical rollout:

1. Set `ACME_DNS_PROVIDER` and the provider credentials.
2. Set `ENS_GASLESS_ENABLED=true`.
3. Start Portal and confirm the log contains both `dnssec configured` and `ens gasless dns import configured`.
4. If the DNSSEC state is `pending`, publish the returned `DS` record at your registrar and wait for propagation.
5. Re-check until the provider DNSSEC state becomes `active`.
6. Verify external resolution with an ENS-aware client after DNSSEC is active.

Registrar DS publication:

- Cloudflare, Google Cloud DNS, and Route53 can sign the zone and return the DS record, but they do not control your registrar unless the domain is registered with the same provider.
- If your registrar is separate, you must copy the DS values from the provider into the registrar's DNSSEC or DS configuration screen.
- Example: if the domain is registered at Namecheap and delegated to Cloudflare nameservers, enable DNSSEC in Cloudflare first, then add the Cloudflare DS record in Namecheap under the domain's `Advanced DNS` DNSSEC section.
- Until the registrar publishes the DS record at the parent zone, provider status typically stays `pending` and ENS gasless resolution may fail even though Portal already wrote the `ENS1 ...` TXT record.

Verification checklist:

- Provider DNSSEC status is `active`.
- `dig +short DS example.com` returns the DS record from the parent zone.
- `dig +short TXT example.com` returns the `ENS1 ...` TXT record.
- ENS-aware resolution returns the expected address for the base domain and each lease hostname.

## 4. Run Relay Server

### 4.1 Create `.env` at repository root

Manual certificate example:

```bash
PORTAL_URL=https://example.com
BOOTSTRAPS=https://bootstrap.example.com
DISCOVERY=true
WIREGUARD_PORT=51820
IDENTITY_PATH=/portal-certs
SNI_PORT=443
ACME_DNS_PROVIDER=
ENS_GASLESS_ENABLED=false
```

Place these files in `IDENTITY_PATH` before startup:

```text
/portal-certs/fullchain.pem
/portal-certs/privatekey.pem
```

Manual certificate + gasless example:

```bash
PORTAL_URL=https://example.com
BOOTSTRAPS=https://bootstrap.example.com
DISCOVERY=true
WIREGUARD_PORT=51820
IDENTITY_PATH=/portal-certs
SNI_PORT=443
ACME_DNS_PROVIDER=cloudflare
CLOUDFLARE_TOKEN=cf_xxxxxxxxxxxxxxxxx
ENS_GASLESS_ENABLED=true
```

In this mode, Portal keeps the manual certificate files but still manages DNSSEC and `ENS1 ...` TXT records through Cloudflare.

Managed Cloudflare example:

```bash
PORTAL_URL=https://example.com
BOOTSTRAPS=https://bootstrap.example.com
DISCOVERY=true
WIREGUARD_PORT=51820
IDENTITY_PATH=/portal-certs
SNI_PORT=443
ACME_DNS_PROVIDER=cloudflare
CLOUDFLARE_TOKEN=cf_xxxxxxxxxxxxxxxxx
ENS_GASLESS_ENABLED=false
```

Route53 example:

```bash
IDENTITY_PATH=/portal-certs
ACME_DNS_PROVIDER=route53
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
AWS_REGION=us-east-1
# Optional override
AWS_HOSTED_ZONE_ID=Z1234567890ABC
# Required only for ENS gasless automation when no ACTIVE KSK already exists.
AWS_DNSSEC_KMS_KEY_ARN=arn:aws:kms:...
ENS_GASLESS_ENABLED=false
```

Google Cloud DNS example:

```bash
IDENTITY_PATH=/portal-certs
ACME_DNS_PROVIDER=gcloud
# Optional when ADC does not expose the project id directly.
GCP_PROJECT_ID=my-gcp-project
# Optional override when the credentials cannot list managed zones.
GCP_MANAGED_ZONE=portal-example-com
# Standard ADC when using a mounted service account file.
GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcp-dns.json
ENS_GASLESS_ENABLED=false
```

Notes:

- For non-apex deployments, set `PORTAL_URL` to the non-apex host value, for example `https://portal.example.com:8443`
- Portal uses the `PORTAL_URL` host for public lease hostnames
- `IDENTITY_PATH` stores the relay state directory inside the container
- Portal stores `identity.json`, `admin_settings.json`, `fullchain.pem`, and `privatekey.pem` under `IDENTITY_PATH`
- The Docker Compose stack stores relay state under `./.portal-certs` on the host

Discovery settings:

```bash
DISCOVERY=true
BOOTSTRAPS=https://bootstrap.example.com
WIREGUARD_PORT=51820
```

- Open `WIREGUARD_PORT/udp` on the host or VM when discovery is enabled.
- The relay always advertises the `PORTAL_URL` host for WireGuard discovery.
- The relay stores its admin secret key in `IDENTITY_PATH/identity.json` and generates one automatically on first startup if the file does not already contain it.
- The relay stores its WireGuard keypair in `IDENTITY_PATH/identity.json`. If that file has no WireGuard key yet, Portal generates one on first discovery startup and saves it back to that file.
- `BOOTSTRAPS` should point at at least one existing relay when you want discovery to join a multi-relay mesh.

If the relay sits behind a reverse proxy or ingress and you want admin/auth and lease IP tracking to use the original client IP, set:

```bash
TRUST_PROXY_HEADERS=true
```

If your proxy source addresses are public or you want a stricter allowlist, also set `TRUSTED_PROXY_CIDRS`.

### 4.2 Start Relay

When using the published Docker image, create the bind-mount directory first and make it writable by UID `65532` (`nonroot` in the distroless image):

```bash
mkdir -p ./.portal-certs
sudo chown 65532:65532 ./.portal-certs
chmod 755 ./.portal-certs
```

If you use manual certificate mode, make sure `fullchain.pem` and `privatekey.pem` already exist in `./.portal-certs` before startup.

If you use `ACME_DNS_PROVIDER=gcloud` with a service account JSON file under Docker Compose, mount the file into the container and set `GOOGLE_APPLICATION_CREDENTIALS` to the in-container path. Example:

```yaml
services:
  portal:
    environment:
      GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/gcp-dns.json
    volumes:
      - ./.portal-certs:/portal-certs
      - ./gcp-dns.json:/run/secrets/gcp-dns.json:ro
```

Then start the stack:

```bash
docker compose up -d
```

## 5. Optional UDP and Raw TCP Port Setup

UDP transport and raw TCP port transport are disabled by default.

### 5.1 Open transport ports on your VM or host

Open these ports in your cloud security group or firewall:

- `WIREGUARD_PORT/udp` when discovery is enabled
- `SNI_PORT/udp`
- `MIN_PORT-MAX_PORT/udp` when UDP transport is enabled
- `MIN_PORT-MAX_PORT/tcp` when raw TCP port transport is enabled

Example with `MIN_PORT=40000` and `MAX_PORT=40009`:

```bash
sudo ufw allow 443/udp
sudo ufw allow 40000:40009/udp
sudo ufw allow 40000:40009/tcp
```

### 5.2 Expose transport ports in Docker

If you use `network_mode: host`, the container uses host transport ports directly.

If you use bridge networking, map the ports explicitly in `docker-compose.yaml`:

```yaml
ports:
  - "443:443/udp"
  - "40000-40009:40000-40009/udp"
  - "40000-40009:40000-40009"
```

Map `SNI_PORT/udp` on the host to the relay's UDP QUIC listener port in the container.
UDP and raw TCP use the same numeric lease range independently, so when both transports are enabled you publish the same `MIN_PORT-MAX_PORT` range once for UDP and once for TCP.

### 5.3 Configure Relay Transport Ports

Set the shared lease range in `.env`, then enable the transports you want.

Example:

```bash
MIN_PORT=40000
MAX_PORT=40009
UDP_ENABLED=true
TCP_ENABLED=true
```

That allocates lease ports `40000-40009` for both UDP and raw TCP. The protocols are independent, so the same numeric port may be used on both transports at the same time.
The SDK datagram backhaul always uses the relay `SNI_PORT`, even if `PORTAL_URL` uses `:4017` for the API.

| Variable | Default | Description |
|---|---|---|
| `MIN_PORT` | `0` | Inclusive minimum lease port shared by UDP and raw TCP (`0` disables the range) |
| `MAX_PORT` | `0` | Inclusive maximum lease port shared by UDP and raw TCP (`0` disables the range) |
| `UDP_ENABLED` | `false` | Enable UDP relay transport |
| `TCP_ENABLED` | `false` | Enable raw TCP port transport |
| `SNI_PORT` | `443` | Public TCP SNI port and QUIC UDP port for relay ingress |

### 5.4 Enable transports in the admin panel

After the relay starts, open `/admin`, enable UDP transport and/or TCP port transport, and set any lease limits you want to enforce.

### 5.5 Optional Linux UDP buffer tuning

For better QUIC performance on Linux:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

To persist this across reboots, add the values to `/etc/sysctl.conf` or a file in `/etc/sysctl.d/`.

## 6. Optional Thumbnail Screenshots

Portal can automatically generate thumbnail screenshots for tunnel apps that don't provide their own. When a tunnel app registers without a `thumbnail` in its metadata, the relay captures a screenshot of the app's public page and serves it as a card background on the dashboard.

This feature is **disabled by default** and entirely optional. Without it, apps without a thumbnail simply show a gradient background.

### 6.1 When to enable

Enable this feature when:

- You want richer visual previews on the relay dashboard
- Most of your tunnel apps don't set a custom thumbnail in their metadata

Skip this feature when:

- You want the smallest possible deployment footprint
- Tunnel apps already provide their own thumbnails
- You're running on resource-constrained servers

### 6.2 How it works

The relay uses a headless Chromium sidecar (`chromedp/headless-shell`, ~200 MB) to render tunnel app pages and capture screenshots. When a tunnel app registers:

1. If the app has no thumbnail and `HEADLESS_SHELL_URL` is configured, the relay queues a screenshot job.
2. A single background worker connects to the headless Chromium via Chrome DevTools Protocol (CDP).
3. The worker navigates to the app's public HTTPS URL, waits for the page to load, and captures a 1280×720 screenshot.
4. The screenshot is JPEG-encoded and cached in memory (max 256 KB per image).
5. On the next dashboard page load, the cached thumbnail is injected into the app's card.

Screenshots are evicted when the lease expires or the app disconnects.

### 6.3 Enable thumbnail screenshots

**Step 1**: Uncomment the headless-shell service in `docker-compose.yml`:

```yaml
services:
  headless-shell:
    image: chromedp/headless-shell:stable
    restart: unless-stopped
```

**Step 2**: Uncomment the `depends_on` in the portal service:

```yaml
  portal:
    depends_on:
      - headless-shell
```

**Step 3**: Uncomment and set `HEADLESS_SHELL_URL` in the portal environment:

```yaml
    environment:
      HEADLESS_SHELL_URL: ${HEADLESS_SHELL_URL:-ws://headless-shell:9222}
```

Or set it in `.env`:

```bash
HEADLESS_SHELL_URL=ws://headless-shell:9222
```

**Step 4**: Restart the stack:

```bash
docker compose up -d
```

### 6.4 Verify

After a tunnel app connects, check the relay logs for:

```
INF thumbnail captured hostname=myapp.portal.example.com size=36209
```

The thumbnail is then served at `/thumbnail/<hostname>` and displayed on the dashboard card.

### 6.5 Disable

Remove or comment out `HEADLESS_SHELL_URL` from `.env` or the docker-compose environment. The headless-shell container can also be removed. Without this variable, the feature is completely inactive with zero overhead.

| Variable | Default | Description |
|---|---|---|
| `HEADLESS_SHELL_URL` | _(empty, disabled)_ | CDP WebSocket URL for headless Chromium sidecar (e.g. `ws://headless-shell:9222`) |

## 7. Auto-Update

Automatically redeploy when a new `ghcr.io/gosuda/portal:latest` image is pushed.

### 7.1 Deploy script

Create `deploy_portal.sh` in your project directory:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker compose pull
docker compose up -d
```

### 7.2 Watcher script

The repository includes `watch_and_deploy.sh`, which polls the remote image digest and runs the deploy script on change.

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `INTERVAL` | `60` | Poll interval in seconds |
| `DEPLOY_SCRIPT` | `deploy_portal.sh` | Path to deploy script |
| `DIGEST_FILE` | `.portal_image_digest` | File storing the last known digest |

### 7.3 Register as systemd service

Set `WorkingDirectory` and `ExecStart` to the directory where `watch_and_deploy.sh` and `deploy_portal.sh` are located:

```bash
sudo tee /etc/systemd/system/portal-watcher.service << 'EOF'
[Unit]
Description=Portal Docker Image Watcher
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=opc
WorkingDirectory=<path-to-project>
ExecStart=/bin/bash <path-to-project>/watch_and_deploy.sh
Restart=always
RestartSec=10
Environment=INTERVAL=60
Environment=DEPLOY_SCRIPT=deploy_portal.sh

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now portal-watcher
```

Adjust `User` to match your environment. Ensure the user belongs to the `docker` group:

```bash
sudo usermod -aG docker opc
```

### 7.4 Verify and monitor

```bash
sudo systemctl status portal-watcher
sudo journalctl -u portal-watcher -f
sudo journalctl -u portal-watcher --since today
```

## 8. Troubleshooting

### 8.1 Ports blocked

Required inbound ports:

- `443/tcp`
- `4017/tcp`
- optional for UDP:
  - `SNI_PORT/udp`
  - `MIN_PORT-MAX_PORT/udp`
- optional for raw TCP:
  - `MIN_PORT-MAX_PORT/tcp`

UFW example with `MIN_PORT=40000` and `MAX_PORT=40009`:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 4017/tcp
sudo ufw allow 443/udp
sudo ufw allow 40000:40009/udp
sudo ufw allow 40000:40009/tcp
sudo ufw status
```

### 8.2 QUIC UDP buffer warnings

If relay logs show `failed to sufficiently increase receive buffer size`, apply the sysctl settings from section 5.5.

### 8.3 Docker DNS resolution fails

If logs show `discover bootstraps failed`, `sync dns records`, or `lookup <host> on 127.0.0.11:53: write: operation not permitted`, Docker is usually using the wrong host resolver config.

On Linux hosts with `systemd-resolved`, point `/etc/resolv.conf` at the upstream resolver list and restart Docker:

```bash
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart docker
docker compose up -d
```

Verify from the container:

```bash
docker exec -it portal-1 nslookup api4.ipify.org
```

### 8.4 Discovery announce warnings

If logs show `relay discovery announce failed` with `404 page not found`, the target bootstrap relay is running an older release or does not serve `/discovery/announce`. This is warning-only: direct `/discovery` polling and explicit relay URLs can still work. The warnings stop once bootstrap relays are upgraded or removed from `BOOTSTRAPS`.

Discovery announce is relay-to-relay only. A relay whose `PORTAL_URL` host is `localhost`, `127.0.0.1`, `::1`, or another loopback/local host is rejected by `/discovery/announce` because other relays and users cannot route to it. To join public discovery, set `PORTAL_URL` to a publicly reachable HTTPS hostname and expose the required TCP/UDP ports.
