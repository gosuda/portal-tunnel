# Game Server Hosting Reference

Read this when the user asks to host, publish, or share a game server (Minecraft, Terraria, Palworld, Valheim, Rust, or any game with a dedicated server). Game hosting uses Portal's raw TCP/UDP transport, not HTTP — the workflow, prerequisites, and verification differ fundamentally from web exposure.

## Game quick-reference

| Game | Transport | Ports | Status | Notes |
|---|---|---|---|---|
| Minecraft Java | TCP | 25565 | Tested | Single TCP port. |
| Minecraft Bedrock | UDP | 19132 | Compatible | Single UDP port. |
| Terraria | TCP | 7777 | Compatible | Single TCP port. |
| Palworld | UDP | 8211 | Experimental | Verify real gameplay before sharing. |
| Valheim | UDP pair | 2456–2457 | Not supported | Requires a base port and the next; Portal allocates one UDP port per lease. |
| Rust | UDP game + query | separate | Not supported | Requires separate public game and query ports. |
| Custom | Ask user | user-specified | — | Identify the protocol (TCP or UDP) and every port before exposing. |

## Hard rule: the relay must support raw transport

Game hosting fails silently if the relay does not have TCP/UDP allocation enabled. Most public relays do **not** — check before promising the user anything:

- Relay must set `TCP_ENABLED` and/or `UDP_ENABLED` with a `MIN_PORT`–`MAX_PORT` range.
- The relay must publish those ports (`MIN_PORT-MAX_PORT:MIN_PORT-MAX_PORT/tcp` and `/udp` in its compose).
- The relay's cloud firewall must allow the same ports.

If no participating relay has raw transport enabled, tell the user they need a relay that does (self-hosted relay with TCP/UDP enabled, or a community relay that supports it). Do not attempt the tunnel — it will fail without a clear error.

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
