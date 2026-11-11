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
- A Linux server with a reachable public IPv4 address, IPv6 address, or both
- A domain name you control (e.g. `relay.example.com`)
- Inbound `443/tcp` open for the dashboard, relay APIs, and SNI tunnel traffic
- Inbound `53/tcp` + `53/udp` open for the embedded authoritative DNS

## Quick Start

Run the relay with a single Docker command:

```bash
mkdir -p ./relay-data
# For a new bind-mount directory on Linux, allow the nonroot container to write.
# Preserve the ownership policy of existing deployments.
sudo chown 65532:65532 ./relay-data
# Optional: place valid fullchain.pem/privatekey.pem in ./relay-data to use a
# manual certificate, only if neither acme-account.key nor acme-registration.json
# is present. Embedded DNS management still runs.
ADMIN_TOKEN=$(openssl rand -hex 32)
# Save ADMIN_TOKEN in your password manager before starting the container.
docker run -d \
  --name portal-relay \
  --restart unless-stopped \
  --cap-add NET_BIND_SERVICE \
  -p 443:443 \
  -p 53:53/tcp \
  -p 53:53/udp \
  -e PORTAL_URL=https://relay.example.com \
  -e IDENTITY_PATH=/portal-certs \
  -e ADMIN_TOKEN="$ADMIN_TOKEN" \
  -v $(pwd)/relay-data:/portal-certs \
  ghcr.io/gosuda/portal:2
```

Replace `relay.example.com` with your domain. Keep the generated
`ADMIN_TOKEN`; it is required for relay admin and policy access.

With a manual certificate and embedded DNS, startup continues when neither
public address family can be discovered. Missing tunnel names return REFUSED
until an address is initialized, and pending discovery retries use an early
backoff before the regular retry interval. After initialization, normal
apex/wildcard refreshes run every three hours. IPv4 and IPv6 are discovered independently; a successful
family updates its records while a failed probe leaves existing records intact.
Errors applying A/AAAA updates still propagate; only discovery failure is deferred.

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
      SNI_PORT: "443"
      IDENTITY_PATH: /portal-certs
      ADMIN_TOKEN: ${ADMIN_TOKEN}
    volumes:
      - ./relay-data:/portal-certs
```

Prepare a new bind-mount directory and provide the saved admin token through
`.env` or an exported `ADMIN_TOKEN`. On Linux, the nonroot container needs write
access to the directory:

```bash
mkdir -p ./relay-data
# For a new directory; preserve existing deployments' ownership policy.
sudo chown 65532:65532 ./relay-data
docker compose up -d
```

### Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORTAL_URL` | `https://localhost` | Canonical public HTTPS origin, including its externally reachable port. |
| `SNI_PORT` | `PORTAL_URL` port, else `443` | Local TCP SNI router listen port; public metadata uses the port from `PORTAL_URL`. |
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

Point the `portal` CLI at your relay with the `--relays` flag:

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
| `A` | `ns.relay.example.com` | `<your server IPv4>` (glue, when IPv4 is reachable) |
| `AAAA` | `ns.relay.example.com` | `<your server IPv6>` (glue, when IPv6 is reachable) |

No wildcard record is needed: the relay synthesizes answers for every tunnel
hostname. The nameserver name is fixed to `ns.<your relay domain>`; publish the
matching glue for each reachable family at the parent zone as shown above. After verifying the delegation, publish the DS exported in the startup log at the parent zone to establish DNSSEC trust. Preserve `IDENTITY_PATH/dnssec-csk.json` in the persistent identity volume; see the [DNSSEC configuration reference](/configuration#embedded-dns) for key permissions, parent setup, and recovery requirements.

IPv6-only deployments publish AAAA glue; dual-stack deployments publish both.
Allow TCP and UDP port 53, the public relay ports, and enabled raw TCP/UDP ranges
through the host, container network, and upstream firewall for every published
family. Discovering a public address does not verify inbound reachability.
A client needs a reachable relay address in a family it can use; see
[IPv4 and IPv6 configuration](/configuration#ipv4-and-ipv6).

## TLS with ACME

Certificates are issued automatically via ACME DNS-01 against the embedded
authoritative DNS server — no DNS provider credentials are required once the
delegation above is in place. External managed backends are supported first-class alternatives to embedded DNS. Operators may retain any vendor for the parent zone and delegate only the relay namespace. For an existing external-backend deployment, the retained settings are:

```yaml
environment:
  ACME_DNS_PROVIDER: cloudflare   # or: gcloud, hetzner, njalla, route53, vultr
  CLOUDFLARE_TOKEN: <your-token>
```

See the [Deployment Guide](/deployment) for full ACME configuration options, credential setup per provider, and managed DNS automation.

## Identity bandwidth limits

The relay defaults to **1 MiB/s (1,048,576 bytes/second)** per service identity,
shared across that identity's HTTP/SNI and raw TCP connections in both
directions. Set the initial default in the relay environment or with
`--default-identity-bps`:

```yaml
environment:
  DEFAULT_IDENTITY_BPS: "1048576"
```

Raise an individual identity's limit in the admin dashboard's BPS settings.
Individual settings persist in `policy.json` and override the relay default
after reconnects and restarts. Setting an identity to `0` explicitly permits
unlimited traffic; identities without a saved override inherit the current
startup default. Setting `DEFAULT_IDENTITY_BPS=0` makes that default unlimited.
Choose **Use relay default** in BPS settings to remove an individual override
and resume inheritance. The admin API exposes the same operation with
`{"identity_key":"name:address","reset_bps":true}` at `/api/policy/leases`.

This limits forwarded streams, not UDP datagrams, cache responses, total relay
bandwidth, or cumulative traffic volume. Programs embedding `portal.Server`
set `ServerConfig.DefaultIdentityBPS` explicitly; its zero value is unlimited.

## Private relay

To serve only tunnels you approve, start the relay in `manual` mode:

```yaml
environment:
  APPROVAL_MODE: "manual"
```

A new tunnel then registers and appears in the admin dashboard, but no traffic
reaches it until you approve it. Meanwhile, `portal expose` logs
`waiting for relay approval`. The tunnel does not need to restart after
approval.

The setting applies on startup, and a mode saved in `policy.json` wins. The
relay saves the mode on any admin change, such as a ban or a bandwidth limit.
So a relay that once ran on `auto` and saved that mode stays open after you set
`APPROVAL_MODE=manual`. The relay logs a warning in that case. Set the mode from
the admin dashboard instead.

An unapproved tunnel routes no traffic, but it still holds its name alias and
any UDP or TCP port it was given, and those ports count against the relay's
capacity limits.

`UNAPPROVED_LEASES_PER_SOURCE` (default `64`) bounds that hold. It is a budget,
not a judgment about who is squatting. A lease that you have not approved, or
have denied or banned, counts against the IP that asked to register it. Over the budget,
a new registration gets `429 rate_limited` with `Retry-After`, and the SDK retries
every 5 minutes, so a tunnel can take that long to register after a slot frees.
This budget never refuses an approved identity, and a repeat registration of one
identity does not count against itself. Concurrent registrations can pass the
limit by a few. Waiting tunnels spend their IP's pre-auth budget, so at the default
pre-auth settings about 50 of them on one IP keep an approved identity on that IP
from registering until they stop. Behind one NAT with that many tunnels, raise the
pre-auth budget or lower this limit. On an `auto` relay only denied and banned
leases count. Each IPv6 address is its own source, so this budget stops one host,
not a network.

### Accept tunnels only from your networks

On an `auto` relay, anyone who can reach it can register a tunnel and serve under
your domain. Keeping the relay's URL to yourself does not hide it: its ACME
certificate puts the hostname in public Certificate Transparency logs. To accept
tunnels only from networks you name, list them in `TUNNEL_SOURCE_CIDRS`:

```yaml
environment:
  TUNNEL_SOURCE_CIDRS: "203.0.113.7/32,10.0.0.0/8"
```

A tunnel from any other address gets `403 source_not_allowed` when it registers
or renews, with a message that names the address the relay saw, such as
`this relay does not accept tunnels from 198.51.100.7`. The tunnel reports that
relay as failed and does not retry it. Visitors are not affected. The list works
with either approval mode, so a relay on `auto` serves new tunnels from your
networks at once, including every identity an embedder creates, and refuses the
rest. Empty, the default, accepts every network, and a value that names no
network, such as `,`, stops the relay at startup. The relay reads the list at
startup and prints it as `tunnel_source_cidrs` in its `starting relay server`
log line, so an empty value there means a misspelled or missing variable left
the relay open. The relay does not warn about a misspelled name when it starts,
but `relay-server config --env-file .env` names it beforehand.

- Write each entry as a CIDR, such as `/32` for one IPv4 address and `/128` for
  one IPv6 address.
- The relay matches the client address it resolves for its pre-auth budget.
  Behind a reverse proxy, set `TRUST_PROXY_HEADERS` and `TRUSTED_PROXY_CIDRS`
  (see the [trust boundary](/deployment#client-addresses-and-the-trust-boundary)),
  or every tunnel appears to come from the proxy. Listing the proxy's address
  instead accepts everyone. The proxy must write `X-Forwarded-For` and
  `X-Real-IP` itself, replacing what the client sent. A header it appends to or
  passes on lets a client put a listed address in it and get in.
- A home connection's address can change, and the list has to follow it. A shared
  address, such as a NAT or a cloud gateway, accepts everyone behind it.
- A tunnel on the relay's own host connects from the address the relay sees, which
  can be `::1` rather than `127.0.0.1`, or a Docker bridge address. The refusal
  names it.
- A relay from before this setting ignores it and accepts every network, so
  recheck the version after a downgrade.

## Optional: Enable TCP/UDP Tunneling

To relay raw TCP or UDP traffic (game servers, databases, etc.), enable the transports and set a port range:

```yaml
environment:
  TCP_ENABLED: "true"
  UDP_ENABLED: "true"
  MIN_PORT: "10000"
  MAX_PORT: "10100"
ports:
  - "443:443/udp" # QUIC backhaul; match the public PORTAL_URL port
  - "10000-10100:10000-10100/tcp"
  - "10000-10100:10000-10100/udp"
```

Allow both the public QUIC backhaul UDP port and the allocated UDP range
through the firewall. The TCP dashboard/SNI mapping remains required.

See [TCP/UDP Tunneling](/tcp-udp-tunneling) for usage details.

## Troubleshooting

**Port already in use**

Port `443` is commonly taken by another process. Check what's listening:

```bash
sudo ss -tlnp | grep ':443'
```

Stop or reconfigure the conflicting service. The bundled public deployment
uses TCP `443` by default. A different public port must be included in
`PORTAL_URL`, published by Docker, and reachable by clients; configure
`SNI_PORT` separately only when the local bind port differs.

**DNS not resolving**

Query the relay's authoritative server directly first, then through a public
resolver:

```bash
dig +short @<your server IP> test.relay.example.com A
dig +short @<your server IP> test.relay.example.com AAAA
dig +short test.relay.example.com A
dig +short test.relay.example.com AAAA
```

If the direct query works but the public one does not, the NS delegation at
the parent zone is missing or not yet propagated. If both fail, confirm the
relay is running and `53/tcp` + `53/udp` are open for the queried address family.
An empty AAAA answer is expected for an IPv4-only relay, and an empty A answer
is expected for an IPv6-only relay.

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
