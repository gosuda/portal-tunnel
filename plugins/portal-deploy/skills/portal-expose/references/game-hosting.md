# Game Server Hosting Reference

Read this when the user asks to host, publish, or share a game server (Minecraft, Terraria, Palworld, Valheim, Rust, or any game with a dedicated server). Game hosting uses Portal's raw TCP/UDP transport, not HTTP — the workflow, prerequisites, and verification differ fundamentally from web exposure.

> **Sync notice**: the Minecraft Java, Terraria, Palworld, Valheim, and Rust rows and the relay-setup facts in this file mirror `docs/src/routes/game-server-hosting/+page.md`; the Minecraft Bedrock row and the Transport limits section mirror the Limitations in `docs/src/routes/tcp-udp-tunneling/+page.md` and have no docs-table counterpart. When Portal's transport capabilities change (new game support, multi-port allocation, etc.), update both files together. The docs page is the human-facing source; this reference is the agent-facing copy.

## Game quick-reference

| Game | Transport | Ports | Status | Notes |
|---|---|---|---|---|
| Minecraft Java | TCP | 25565 | Tested | Single TCP port. |
| Minecraft Bedrock | UDP | 19132 | Untested | Portal caps UDP datagrams at 1350 bytes and Bedrock's default MTU is larger; do not promise Bedrock support. |
| Terraria | TCP | 7777 | Compatible | Single TCP port. |
| Palworld | UDP | 8211 | Experimental | Verify real gameplay before sharing. |
| Valheim | UDP pair | 2456–2457 | Not supported yet | Requires a base port and the next; Portal allocates one UDP port per lease. |
| Rust | UDP game + query | separate | Not supported yet | Requires separate public game and query ports. |
| Custom | Ask user | user-specified | — | Identify the protocol (TCP or UDP) and every port before exposing. |

## Hard rule: the relay must support raw transport

Game hosting fails silently if the relay does not have TCP/UDP allocation enabled. Most public relays do **not** — check before promising the user anything:

- Relay must set `TCP_ENABLED` and/or `UDP_ENABLED` with a `MIN_PORT`–`MAX_PORT` range.
- The relay must publish those ports (`MIN_PORT-MAX_PORT:MIN_PORT-MAX_PORT/tcp` and `/udp` in its compose).
- For UDP, the relay must additionally publish `443/udp`, the QUIC backhaul on the public `PORTAL_URL` port, not only the lease range. The bundled `docker-compose.yml` ships that line commented out.
- The relay's cloud firewall must allow the same ports.

If no participating relay has raw transport enabled, tell the user they need a relay that does (self-hosted relay with TCP/UDP enabled, or a community relay that supports it). Do not attempt the tunnel — it will fail without a clear error.

## Transport limits

- UDP datagrams above 1350 bytes are dropped by the relay; check the game's packet size or MTU settings before promising UDP support.
- UDP flows idle for 5 minutes are forgotten by the relay; protocols that can go quiet need keepalives.
- One lease may carry both `--tcp` and `--udp` (`portal expose --tcp --udp --udp-addr localhost:19132 localhost:25565`); both ports come from the same `MIN_PORT`–`MAX_PORT` range.
- A relay serves at most `MAX_PORT - MIN_PORT + 1` concurrent leases per protocol; size the range for the expected number of simultaneous tunnels.
- Raw TCP/UDP adds no Portal tenant TLS, so game traffic is visible to the relay; rely on the game's own password or allowlist.

## Workflow

### 1. Identify the game and its requirements

Look up the game in the table above, or ask the user for the protocol and port(s). If the game needs multiple related UDP ports (Valheim, Rust), report that Portal cannot support it yet rather than partially exposing.

### 2. Check relay support

Confirm the chosen relay (or relay pool) has the needed transport enabled. `portal expose` with `--tcp` or `--udp` will fail or hang if the relay cannot allocate a port.

### 3. Start the local game server

The game server must be running and listening on its expected port before the tunnel opens. Verify with a local connection (e.g., `nc -z 127.0.0.1 25565` for TCP, or a protocol-appropriate UDP probe).

### 4. Expose with the correct transport

```sh
portal expose <game-port> --udp --name <name>
```

UDP-only Palworld example; `--udp-addr` is needed only when the UDP port differs from the positional target:

```sh
portal expose 127.0.0.1:8211 --udp --name <name>
```

or for TCP:

```sh
portal expose <game-port> --tcp --name <name>
```

Game servers are long-lived — recommend the persistent agent config for anything beyond a one-off session.

### 5. Verify the raw transport endpoint

Unlike HTTP tunnels, raw transports log `raw transport endpoints allocated` with `tcp_addr` and/or `udp_addr` — **not** a `service ready at <URL>` line. Do not wait for an HTTPS URL.

Verify by connecting through the public endpoint:
- TCP: attempt a connection to the `tcp_addr` (e.g., `nc -z <host> <port>`)
- UDP: send a protocol-appropriate packet and expect a response (game-dependent; a no-response UDP probe proves nothing)

A successful local port check is not sufficient — verify through the public endpoint.

### 6. Hand off

Report: the `tcp_addr` or `udp_addr` for players to connect to, which game and version is hosted, and the tunnel lifecycle (persistent agent or foreground). Players connect directly to `host:port` — they do not install Portal.

## Failure rules

- Game needs a port group Portal cannot allocate: report the limitation, do not partially expose.
- No relay with raw transport available: report before attempting, suggest a self-hosted relay.
- Public endpoint unreachable while local game server works: check the relay's port publishing and firewall first.
- UDP probe gets no response: some game servers do not respond to empty probes — try connecting with the actual game client before declaring failure.
