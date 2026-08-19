---
name: portal-relay
description: Set up and run a public Portal relay on any Linux host with a public IP — Docker Compose deployment, embedded authoritative DNS with one-time NS delegation, optional TCP/UDP lease ports for game hosting, and registration in the public relay pool. Use when the user asks to run their own relay, contribute a relay to the Portal network, self-host a relay instead of using public ones, or open a relay with game-server support. Do not use for exposing a local service (portal-expose) or for accessing a CLI agent remotely.
license: MIT
---

# Run a Public Portal Relay

A relay is the public edge of the Portal network: it terminates nothing, sees only ciphertext, and forwards tunnel traffic. Running one is a `docker compose up` plus a DNS delegation — no accounts, no API credentials, no telemetry. This skill walks the agent through the full setup, verification, and public pool registration.

## Prerequisites (hosting-agnostic)

Any Linux host with:

- A **public IPv4 address** and the ability to open ports
- **Docker and Docker Compose v2**
- Open inbound: `443/tcp` (tunnel traffic), `53/tcp` + `53/udp` (embedded DNS), `51820/udp` (overlay, when discovery is enabled)
- A **domain name** you can delegate a subdomain of

Bandwidth guidance: web/API tunnels are lightweight (tens of GB/month for typical use). Game hosting via TCP/UDP leases consumes more (hundreds of GB to TB/month). Any budget VPS, cloud instance, or home server with a static IP qualifies. Free-tier cloud instances (Oracle Ampere A1, for example) work well because the relay binary is a single Go process with minimal memory and CPU.

## Hard rules

- The relay's admin token (`ADMIN_TOKEN`) is a credential — generate a long random value, never commit or log it.
- The identity directory (`IDENTITY_PATH`) contains private key material — keep it out of version control and backups you don't control.
- Do not expose the API port (`4017`) publicly. It is reached through the relay's own SNI router.
- If enabling TCP/UDP leases for game hosting, the host firewall or cloud security group must allow the same port range that Docker publishes. Half-open ranges cause silent failures.

## Workflow

### 1. Verify the host

- Check Docker: `docker compose version`
- Check public IP reachability: confirm the host's firewall allows inbound on the required ports
- Confirm a domain or subdomain is available for delegation (e.g., `relay.example.com`)

### 2. Set up the delegation

The embedded authoritative DNS server (default since #311) eliminates the need for external DNS provider credentials. At the parent zone's DNS management, create two records:

| Type | Name | Value |
|---|---|---|
| `NS` | `relay.example.com` | `ns.relay.example.com` |
| `A` | `ns.relay.example.com` | `<public IP>` (glue) |

No wildcard record is needed — the relay synthesizes A answers for every tunnel hostname under its zone. See the [Configuration Reference](https://gosuda.github.io/portal-tunnel/configuration) for the canonical embedded DNS documentation.

### 3. Deploy

Create `.env` and `docker-compose.yml` per the standard relay deployment:

```dotenv
PORTAL_URL=https://relay.example.com
ADMIN_TOKEN=<long random value>
DISCOVERY=true
```

The bundled `docker-compose.yml` in the repository already includes:
- `cap_add: NET_BIND_SERVICE` (for binding port 53 as a nonroot container)
- Published ports: `443/tcp`, `53/tcp`, `53/udp`, `51820/udp`

```sh
docker compose pull
docker compose up -d
```

### 4. Optional: enable TCP/UDP leases for game hosting

Most public relays do not enable raw transport. If the user wants to support game servers (Minecraft, Terraria, etc.) or other TCP/UDP services through their relay:

```dotenv
TCP_ENABLED=true
UDP_ENABLED=true
MIN_PORT=50000
MAX_PORT=50009
```

And publish the lease range in the compose:

```yaml
ports:
  - "50000-50009:50000-50009/tcp"
  - "50000-50009:50000-50009/udp"
```

The host's cloud firewall or security group must allow the same ports. See `references/game-hosting.md` in the portal-expose skill for game-specific knowledge.

### 5. Verify

```sh
# Health check
curl -fsS https://relay.example.com/api/healthz

# Tunnel egress: expose something through this relay from another machine
portal expose 3000 --relays https://relay.example.com --discovery=false

# DNS delegation
dig +short @<public IP> relay.example.com NS
```

If game hosting is enabled, also verify a raw transport allocation by exposing with `--tcp` or `--udp`.

### 6. Register in the public pool

Submit a PR to add the relay URL to `registry.json` in the portal-tunnel repository. This makes the relay discoverable by all Portal clients through the default registry. The maintainers review and merge.

### 7. Hand off

Report: the relay URL, whether game hosting (TCP/UDP leases) is enabled, the identity directory path (must stay backed up and private), the admin token location, and the update procedure (`docker compose pull && docker compose up -d` tracks the latest release).

## Failure rules

- `healthz` unreachable: check Docker logs (`docker compose logs relay`) before assuming a DNS issue.
- DNS delegation not resolving: verify the glue A record at the parent zone with `dig @<parent NS> ns.relay.example.com`.
- Game hosting port allocation fails: confirm the host firewall allows the `MIN_PORT`–`MAX_PORT` range, not just Docker's published ports.
- Relay starts but tunnels cannot connect: verify port `443/tcp` is open inbound — the relay's SNI router listens there.
- Identity directory lost: the relay generates a new identity and cannot serve tunnels under the old hostnames — back up `IDENTITY_PATH` before migrations.
