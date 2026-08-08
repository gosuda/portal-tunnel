---
title: Game Server Hosting
description: Expose self-hosted game servers through Portal without opening ports on the game host.
---

# Game Server Hosting

Portal exposes a game server running on your own machine through a public relay.
Players connect to the relay's assigned `host:port`; they do not install Portal.

```text
Game client -> Relay public port -> Portal tunnel -> Local game server
```

The game host needs outbound access to the relay. The relay, not the game host,
needs a public IP address and open TCP or UDP lease ports.

## Compatibility

| Game | Transport | Status | Notes |
| --- | --- | --- | --- |
| Minecraft Java Edition | TCP | Tested | One public TCP endpoint. |
| Terraria | TCP | Compatible | One public TCP endpoint. |
| Palworld | UDP | Experimental | Test direct joins and real gameplay before sharing publicly. |
| Valheim | UDP port pair | Not supported yet | Requires a base port and the following port. |
| Rust | UDP game + query ports | Not supported yet | Requires separate public game and query ports. |

Portal currently allocates one TCP port and one UDP port per lease. It does not
reserve a related group of UDP ports or preserve a game's public port layout.
That is why Valheim and Rust are not ready yet.

## Relay Setup

For TCP game servers, enable TCP allocation and publish the lease range:

```yaml
environment:
  TCP_ENABLED: "true"
  MIN_PORT: "50000"
  MAX_PORT: "50009"
ports:
  - "443:443"
  - "50000-50009:50000-50009/tcp"
```

For UDP game servers, also enable UDP, publish the UDP lease range, and expose
the relay's QUIC backhaul port:

```yaml
environment:
  UDP_ENABLED: "true"
  MIN_PORT: "50000"
  MAX_PORT: "50009"
ports:
  - "443:443"
  - "443:443/udp"
  - "50000-50009:50000-50009/udp"
```

Your cloud firewall or security group must allow the same public ports.

## Minecraft Java Edition

Run the Minecraft server locally on its default TCP port, `25565`, then start
the tunnel:

```bash
portal expose localhost:25565 \
  --tcp \
  --name minecraft \
  --relays https://relay.example.com \
  --discovery=false
```

Portal logs the assigned endpoint:

```text
raw transport endpoints allocated tcp_addr=minecraft.relay.example.com:50000
```

In Minecraft Java Edition, add a multiplayer server with:

```text
minecraft.relay.example.com:50000
```

Do not add `https://`. Test from a different network before sharing the server
with friends.

## Terraria

Terraria's dedicated server uses TCP port `7777` by default. Start the server,
then expose it with raw TCP:

```bash
portal expose localhost:7777 \
  --tcp \
  --name terraria \
  --relays https://relay.example.com \
  --discovery=false
```

Players use the allocated `host:port` in Terraria's **Join via IP** flow. The
[Terraria dedicated server guide](https://terraria.wiki.gg/wiki/Dedicated_Server)
documents the default TCP port and the direct-IP join flow.

## Palworld

Palworld's default game port is UDP `8211`. Start the dedicated server locally,
then expose its UDP listener:

```bash
portal expose localhost:8211 \
  --udp \
  --udp-addr localhost:8211 \
  --name palworld \
  --relays https://relay.example.com \
  --discovery=false
```

For a community server, configure Palworld's advertised `publicip` and
`publicport` with the relay's public IPv4 address and the assigned UDP port.
Those values describe the public relay endpoint; the local Palworld listener
can remain on `8211`. See the [Palworld server arguments](https://docs.palworldgame.com/settings-and-operation/arguments/).

Portal UDP datagrams are currently limited to 1350 bytes and inactive flows are
removed after 5 minutes. Direct joins and sustained gameplay must both be
tested before treating a Palworld server as production-ready.

## Valheim and Rust

Do not describe these as supported through Portal yet.

- Valheim uses the configured UDP port and that port plus one; its default pair
  is `2456-2457`. See the [Valheim dedicated server guide](https://valheim.com/support/a-guide-to-dedicated-servers/).
- Rust requires separate UDP `server.port` and `server.queryport` endpoints for
  player connections and server browser queries. See [Rust's server guide](https://wiki.facepunch.com/rust/Creating-a-server).

Supporting them needs grouped UDP port allocation and per-port public-to-local
mapping. Running separate single-port tunnels does not provide the stable,
related public ports these games expect.

## Security and Operations

- Raw TCP and UDP transports do not add Portal tenant TLS. Treat unencrypted
  game traffic as visible to the relay network.
- Use game passwords, allowlists, or both before giving an endpoint to others.
- Keep the tunnel process and game server running. Stopping either makes the
  assigned endpoint unavailable.
- Back up worlds and test from an external network, such as a mobile hotspot or
  a friend's connection.
