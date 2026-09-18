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
      -> root host: Admin/API handler (in-process handoff)
          -> /api/*, /sdk/*, /discovery*, /v1/sign
          -> embedded React SPA for /, /admin, and client routes
      -> registered wildcard host: tunnel ingress
```

The SNI router is the single ingress: it inspects each TLS handshake and hands
root-host connections in-process to the Admin/API handler, so there is no
separate API listener and nothing else to publish.

This topology assumes Portal owns public `443/tcp`. If that port already
belongs to something else on the host, see
[Running Behind an Existing Reverse Proxy](#running-behind-an-existing-reverse-proxy).

## Prerequisites

- A public Linux server with Docker and Docker Compose.
- A public hostname such as `portal.example.com`.
- A one-time NS delegation at the parent zone: `NS portal.example.com -> ns.portal.example.com` with a glue `A` record pointing at the relay public IP. See the [Configuration Reference](/configuration#embedded-dns) for the canonical embedded DNS details.
- Inbound `443/tcp`, `53/tcp` + `53/udp` for the embedded authoritative DNS.
- Certificates for the root and wildcard names are issued automatically via ACME DNS-01 against the embedded authoritative DNS.

## Configuration

Create `.env` next to `docker-compose.yml`:

```dotenv
PORTAL_URL=https://portal.example.com
ADMIN_TOKEN=replace-with-a-long-random-value
LANDING_PAGE_ENABLED=false

DISCOVERY=false
BOOTSTRAPS=
IVNP_CONFIG=

# Embedded authoritative DNS is the default provider and needs no API
# credentials once the NS delegation above is in place. External providers
# (cloudflare, gcloud, hetzner, njalla, route53, vultr) are supported
# first-class backends when selected explicitly.
ACME_DNS_PROVIDER=
EMBEDDED_DNS_PORT=53
```

Embedded DNS logs its DS as soon as the local DNS listeners start; startup does not check delegation. After NS/glue delegation is reachable, publish the DS printed at startup at the parent zone. Persist `IDENTITY_PATH/dnssec-csk.json` with the identity volume across container replacement and backup/restore; replacing this key without coordinating the parent DS breaks DNSSEC validation. See [Embedded DNS](/configuration#embedded-dns) for the complete DNSSEC setup and key-storage requirements. Manual certificate overrides remain supported.

`LANDING_PAGE_ENABLED` supplies the initial value. Changes made from the admin
dashboard are stored in `IDENTITY_PATH/policy.json` and survive restarts.

To enable the optional IVNP overlay, set `DISCOVERY=true`, mount an IVNP
`RouterConfig` JSON file, and set `IVNP_CONFIG` to its container path. A file
containing `{}` uses in-memory router state and needs no writable state mount.
Replace legacy `ivnp.conf` files with the new JSON format. For persistent router
state, explicitly configure and mount a dedicated private directory as described
in [IVNP overlay configuration](/configuration#ivnp-overlay).
Invalid overlay configuration fails startup. Destination warmup runs in the
background; a runtime overlay failure leaves public ingress and direct reverse
transport running. See [IVNP overlay transport](/architecture#optional-relay-overlay).

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

The certificate must cover the Portal root hostname and the tunnel hostnames,
normally through a wildcard SAN. Even uncached tunnels use this certificate
through the relay-backed keyless signer. Manual files override issuance only
when neither `acme-account.key` nor `acme-registration.json` exists in the state
directory; DNS and ECH management still run.

## Deploy

```bash
mkdir -p ./.portal-certs
# For a new bind-mount directory on Linux, allow the nonroot container to write.
# Preserve the ownership policy of existing deployments.
sudo chown 65532:65532 ./.portal-certs
docker compose pull portal
docker compose up -d --force-recreate portal
```

For a local source build:

```bash
docker compose up -d --build --force-recreate portal
```

Name the Portal service explicitly when the Compose project contains unrelated
services. Do not use `--remove-orphans` on a shared project; remove obsolete
containers individually after confirming their ownership.

The Compose stack publishes:

| Port | Purpose |
|---|---|
| `443/tcp` | Portal HTTPS, SPA, APIs, and SNI tunnel ingress |
| `53/tcp` + `53/udp` | Embedded authoritative DNS for the delegated relay zone |
| configured lease range | Optional UDP and raw TCP leases |

Port `80/tcp` is optional. To enable the built-in redirect listener, set
`HTTP_REDIRECT_ENABLED=true` and publish `80:80`. It redirects to the canonical
`PORTAL_URL`, discarding the request path and query; it does not redirect tenant
hostnames. See [HTTP redirect configuration](/configuration#optional-http-redirect-listener).
An external redirect service is also possible, but must not terminate wildcard
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

## Upgrading

Clients and relays perform an exact protocol version match. v2.4.0 ships
protocol version 9 for both the tunnel handshake and discovery, so v2.3.x
clients are rejected by v2.4.0+ relays (`relay sdk protocol version mismatch`)
and vice versa. Upgrade relays and the tunnel clients that dial them together:
a relay upgraded first rejects every older client until the clients catch up
(`portal update`).

## Running Behind an Existing Reverse Proxy

Portal expects to own public `443/tcp`. On a host that already serves other
sites from that port, it cannot simply be pointed at: Portal's SNI router
**closes any hostname it has no lease for**, so a shared socket would drop
every request meant for those other sites.

The proxy keeps the port and hands Portal the hostnames that belong to it.
Example configurations: [Compose override](/examples/reverse-proxy/compose.override.yaml)
and [nginx configuration](/examples/reverse-proxy/nginx.conf).

### One topology: nginx in a container beside Portal

nginx runs on the same Compose network as Portal and owns the public HTTPS
port. It reaches Portal as `portal:443` on that network. Portal still publishes
`53/tcp` and `53/udp` for the default embedded DNS provider; retain any enabled
UDP backhaul and lease-port mappings in the override.

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

`SNI_PORT` stays `443` inside the container. The SNI router is Portal's single
ingress: the Admin/API handler is served through it in-process, so there is no
separate API port to wire around. The public port in `PORTAL_URL`, not this
local listener setting, goes into the ECH `HTTPS` record.

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
proxy_set_header X-Real-IP $remote_addr;
```

`$proxy_add_x_forwarded_for` keeps whatever the visitor sent and appends the
peer. Portal trusts the *first* entry, so a request carrying
`X-Forwarded-For: 10.0.0.9` from the Internet arrives as `10.0.0.9, <real>` and
is read as `10.0.0.9` — a source rate-limit bypass. `$remote_addr` has already
been restored from the PROXY header, so it is both correct and unspoofable.

Enable `TRUST_PROXY_HEADERS` and set `TRUSTED_PROXY_CIDRS` to **the proxy's own
address as a `/32`** (`/128` for IPv6). An empty allowlist trusts no proxies,
including private and loopback peers, and Portal uses the socket address.
Do not allowlist an entire private subnet: on a Docker host that would let
other containers choose their client address and bypass source limits.

That address has to be *fixed*. Compose assigns container addresses
dynamically, so a `/32` matching whatever nginx got today stops matching the
next time it is recreated — and the failure is silent: everything still works,
Portal just ignores the forwarded address and starts applying rate
limits to nginx instead of to visitors. Give the network its own IPAM and pin
nginx into it:

```yaml
services:
  nginx:
    networks:
      edge:
        ipv4_address: 172.31.240.2      # TRUSTED_PROXY_CIDRS=172.31.240.2/32
  portal:
    networks: [edge]

networks:
  edge:
    ipam:
      config:
        - subnet: 172.31.240.0/24
```

Compose's implicit default network does not accept `ipv4_address`, which is why
the network is declared. Check the subnet does not overlap something already on
the host with
`docker network inspect $(docker network ls -q) --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'`.

### Terminating the root host conflicts with ECH

Passing the root host through leaves Portal with no client address at all: it
reads `X-Forwarded-For` and `X-Real-IP` only, and a pass-through carries no HTTP
layer to put them in. Terminating it recovers that, but check one thing first.

When a DNS provider is configured, Portal publishes an `HTTPS` record carrying
`ech=` for its own hostname and installs the matching key **only on its own SNI
listener**. An nginx terminator has neither, so ECH-capable clients that read
the record can fail the connection before any request arrives.

An empty `ACME_DNS_PROVIDER` selects embedded DNS; it does not disable ECH publication. Valid manual certificates override issuance only when neither `acme-account.key` nor `acme-registration.json` exists in `IDENTITY_PATH`. Embedded DNS still initializes and refreshes its synthesized A records, and the selected provider still publishes ECH records; external providers therefore still need API access for that publication. For a public relay with managed DNS, pass the root host through: terminating it elsewhere breaks the ECH it advertises.

Pass-through is the default in the example for that reason.

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

## Troubleshooting

### Port 443 Is Already Allocated

Identify what holds the port first:

```bash
sudo ss -tlnp | grep ':443\b'
```

If the listener belongs to an obsolete deployment, stop only that deployment's
service after confirming ownership. If it serves other sites, keep it running
and use [the reverse-proxy topology](#running-behind-an-existing-reverse-proxy).

### SPA Routes Return 404

When `PORTAL_FRONTEND_DIR` is empty, Portal serves its embedded frontend.
When it is set, confirm the mounted directory contains
`index.html` and all asset paths expected by that file. `/admin` and other
non-reserved client routes fall back to the selected SPA's `index.html`.

### Certificate Errors

Confirm `PORTAL_URL` matches the certificate root hostname and inspect the
certificate files under `IDENTITY_PATH`. With the embedded DNS provider,
confirm the delegation is visible (`dig @<relay public IP> portal.example.com NS`)
and that `53/tcp` + `53/udp` are reachable. With an external provider, verify
the DNS API token has permission to update the selected zone.
