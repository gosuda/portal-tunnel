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

This topology assumes Portal owns public `443/tcp`. If that port already
belongs to something else on the host, see
[Running Behind an Existing Reverse Proxy](#running-behind-an-existing-reverse-proxy).

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
```

The certificate must cover the Portal root hostname. A wildcard certificate is
also required when wildcard tunnel names terminate TLS at Portal.

## Deploy

```bash
mkdir -p ./.portal-certs
docker compose pull portal
docker compose up -d --force-recreate portal
```

For a local source build:

```bash
docker compose up -d --build --force-recreate portal
```

`--remove-orphans` is deliberately absent. It is useful once, to clear the
containers a superseded topology left behind, and dangerous in a project shared
with unrelated services. Remove those containers by name instead — see
[Migration From the Split Stack](#migration-from-the-split-stack).

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

## Running Behind an Existing Reverse Proxy

Portal expects to own public `443/tcp`. On a host that already serves other
sites from that port, it cannot simply be pointed at: Portal's SNI router
**closes any hostname it has no lease for**, so a shared socket would drop
every request meant for those other sites.

The proxy keeps the port and hands Portal the hostnames that belong to it.
Complete, tested configurations are in
`docs/static/examples/reverse-proxy/`.

### One topology: nginx in a container beside Portal

nginx runs as a service on the same Compose network as Portal. Only nginx
publishes host ports. Portal publishes no TCP port at all and is reached as
`portal:443` and `portal:4017` over that network.

```text
host :443 -> nginx container
               :443  stream, ssl_preread, sends PROXY protocol
                 *.portal.example.com -> :8444 -> strips PROXY -> portal:443
                 portal.example.com   -> :8444 -> strips PROXY -> portal:443
                 anything else        -> :8443 -> nginx http, other sites
```

Mixing this with a host-loopback port mapping does not work: if Portal also
published `127.0.0.1:8443`, nginx's own listener on that address could not
bind. Pick this topology or a host nginx reaching Portal over published ports —
not both.

`SNI_PORT` stays `443` inside the container. Portal reaches its own API listener
through its SNI router, and that port is what goes into the ECH `HTTPS` record.

### Lease hostnames must pass through, unmodified

Terminating TLS for `*.portal.example.com` breaks tunnels: clients started with
`--ban-mitm` probe for termination and drop a relay that does it, and it
disables keyless TLS and Encrypted Client Hello, both of which need the
handshake itself to reach Portal.

Two things in an nginx `stream` block break this quietly.

**The map needs `hostnames;`.** Without it, `map` compares keys as literal
strings and `*.portal.example.com` matches nothing, so every lease hostname
falls through to `default` and is answered by the HTTP terminator instead of
Portal:

```nginx
map $ssl_preread_server_name $portal_backend {
    hostnames;                              # required for the wildcard to match
    *.portal.example.com  127.0.0.1:8444;
    portal.example.com    127.0.0.1:8444;
    default               127.0.0.1:8443;
}
```

**The PROXY header must be stripped before Portal.** `proxy_protocol on` is a
server-level directive, so the `:443` listener sends the header to *every*
destination it selects. Portal does not parse the PROXY protocol: it would read
`PROXY TCP4 ...` where it expects a TLS ClientHello and close the connection.
Send the lease path through a stage that consumes the header first:

```nginx
server {
    listen 127.0.0.1:8444 proxy_protocol;   # consumes it
    set $portal_sni portal:443;             # variable, so it resolves per request
    proxy_pass $portal_sni;                 # no proxy_protocol on: plain TLS onward
}
```

### Client addresses, and the trust boundary

An SNI router forwarding to a local port opens a new connection, so the
terminating listener sees the router rather than the visitor. `proxy_protocol on`
carries the original address, and the http block recovers it:

```nginx
set_real_ip_from 127.0.0.1;     # trust only the loopback hop
real_ip_header proxy_protocol;
```

This is what gives the *other sites* on the box their real client addresses. For
Portal itself it only matters if you terminate the root host — see below.

If you do, **overwrite `X-Forwarded-For` rather than appending to it**:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;    # not $proxy_add_x_forwarded_for
```

`$proxy_add_x_forwarded_for` keeps whatever the visitor sent and appends the
peer. Portal trusts the *first* entry, so a request carrying
`X-Forwarded-For: 10.0.0.9` from the Internet arrives as `10.0.0.9, <real>` and
is read as `10.0.0.9` — an `/api/policy/ips` bypass. `$remote_addr` has already
been restored from the PROXY header, so it is both correct and unspoofable.

Set `TRUSTED_PROXY_CIDRS` to **the proxy's own address as a `/32`**, not the
default private ranges. The default trusts every RFC 1918 address, which on a
Docker host means every container.

### Terminating the root host conflicts with ECH

Passing the root host through leaves Portal with no client address at all: it
reads `X-Forwarded-For` and `X-Real-IP` only, and a pass-through carries no HTTP
layer to put them in. Terminating it recovers that, but check one thing first.

When a DNS provider is configured, Portal publishes an `HTTPS` record carrying
`ech=` for its own hostname and installs the matching key **only on its own API
listener**. An nginx terminator has neither, so ECH-capable clients that read
the record can fail the connection before any request arrives.

`SyncECHConfig` is a no-op when no DNS provider is configured, so:

| `ACME_DNS_PROVIDER` | Root host |
|---|---|
| set (managed issuance) | pass through — terminating breaks the ECH it advertises |
| empty (manual certificates) | may be terminated, which is what recovers client addresses |

Pass-through is the default in the example for that reason.

### Publishing Portal's ports

```yaml
services:
  portal:
    ports: !override
      - "${WIREGUARD_PORT:-51820}:${WIREGUARD_PORT:-51820}/udp"
```

`!override` replaces the base `ports` list rather than appending to it; without
it Compose merges both and still tries to bind `443`. It requires Docker Compose
2.24.4 or newer.

Because it *replaces*, this list must carry **every mapping the deployment had
enabled**. The bundled file publishes TCP 443 and the WireGuard port and
comments out three more — `443/udp` for QUIC backhaul, the `MIN_PORT`–`MAX_PORT`
UDP range, and the same range for raw TCP leases. Anything left out here stops
being published, silently, and tunnels that used it stop working.

### Sharing a Compose project with unrelated services

A host like this usually runs Portal alongside services that have nothing to do
with it. Compose commands operate on the whole project by default, so name the
service explicitly every time:

```bash
docker compose up -d portal        # not: docker compose up -d
docker compose stop portal         # not: docker compose down
```

Never pass `--remove-orphans` on a shared project. It deletes every container
in the project that the current file does not define, which includes services
that belong to other stacks.

### Verifying without a regression hunt

Record how the host answers **before** changing anything, so that an error found
afterwards can be attributed rather than investigated:

```bash
# One line per host, with a path its clients actually use.
cat > probe.txt <<'PROBE'
portal.example.com   /api/healthz
other-site.example   /
PROBE

probe() {
  while read -r host path; do
    [ -z "$host" ] && continue
    printf '%-32s %-16s %s\n' "$host" "$path" \
      "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$host$path")"
  done < probe.txt
}

probe > baseline.txt
```

Compare with `probe | diff baseline.txt -` afterwards. Judge by the difference,
not by whether a code looks healthy: `/` is not a valid request for every host,
and a WebSocket-only endpoint answers a plain `GET` with nothing at all, which a
proxy correctly reports as `502`.

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

1. Confirm `./.portal-certs` contains the Portal certificate and state. It holds
   the relay identity: losing it makes this a different relay.
2. Pull or build the new single Portal image.
3. Stop the old stack so it releases public port 443.
4. Remove the superseded `nginx`, `portal-api` and `portal-frontend` services,
   then start `portal`.

   Do this through the **old** Compose file. Those services did not set
   `container_name`, so their containers are named `<project>-portal-api-1`
   rather than `portal-api`, and `docker stop portal-api` fails with
   `No such container`. Keep the old file until this step is done:

   ```bash
   docker compose -f docker-compose.old.yml ps            # confirm the real names
   docker compose -f docker-compose.old.yml stop nginx portal-api portal-frontend
   docker compose -f docker-compose.old.yml rm -f nginx portal-api portal-frontend
   docker compose up -d portal
   ```

   If the old file is already gone, resolve the names through Compose's own
   labels instead of guessing:

   ```bash
   docker ps -a --filter label=com.docker.compose.service=portal-api \
     --format '{{.Names}}'
   ```

   Not `--remove-orphans`: it deletes every container in the project that the
   current file does not define, including services belonging to other stacks
   when the project is shared.

5. Verify the SPA, relay APIs, and at least one wildcard tunnel.

The old edge configuration and its separate browser certificate are no longer
used. Portal owns the public certificate and performs only one TLS handshake
for root-host requests.

## Troubleshooting

### Port 443 Is Already Allocated

Identify what holds the port first:

```bash
sudo ss -tlnp | grep ':443\b'
```

If it is a superseded Portal edge container, stop and remove it by name, then
start Portal:

```bash
docker stop <old-edge-container>
docker rm   <old-edge-container>
docker compose up -d portal
```

If it is something that has to keep serving — an nginx fronting other sites, for
example — Portal cannot take the port from it and must not try. See
[Running Behind an Existing Reverse Proxy](#running-behind-an-existing-reverse-proxy).

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
