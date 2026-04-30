---
title: TCP/UDP Tunneling
description: Tunnel raw TCP and UDP services like game servers through Portal.
---

# TCP/UDP Tunneling

Portal supports raw TCP and UDP tunneling in addition to its default HTTPS proxy mode. This lets you expose services that don't speak HTTP — game servers, databases, custom binary protocols, and anything that needs a dedicated port on the public internet.

## Overview

By default, Portal routes traffic through TLS SNI multiplexing on port 443 — perfect for web services. For everything else:

- **Raw TCP** — allocates a dedicated public port on the relay. Clients connect to `relay-host:port` with no TLS wrapping, exactly as if the service were directly internet-facing.
- **UDP** — transports datagrams over a QUIC backhaul between the client and your local service. Ideal for game servers, VoIP, and other latency-sensitive protocols.

Both modes require the relay server to have a port range configured and the corresponding transport enabled.

## Relay Configuration

Enable TCP and UDP transports on your relay by setting these environment variables:

| Variable | Default | Description |
|---|---|---|
| `TCP_ENABLED` | `false` | Enable raw TCP port allocation |
| `UDP_ENABLED` | `false` | Enable UDP/QUIC datagram transport |
| `MIN_PORT` | `0` (disabled) | Inclusive minimum of the port allocation range |
| `MAX_PORT` | `0` (disabled) | Inclusive maximum of the port allocation range |

`MIN_PORT` and `MAX_PORT` are shared between TCP and UDP. Both transports draw from the same pool. Setting either to `0` disables port allocation entirely.

<div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 0.75rem 1rem; border-radius: 0.375rem; margin: 1rem 0;">
  <strong>Note:</strong> The relay's firewall or cloud security group must allow inbound traffic on the entire <code>MIN_PORT</code>–<code>MAX_PORT</code> range, for both TCP and UDP protocols, depending on which transports you enable.
</div>

## TCP Tunneling

Raw TCP tunneling allocates a dedicated port on the relay. Incoming TCP connections to that port are bridged directly to your local service with no TLS.

### Step 1 — Configure the relay

```bash
TCP_ENABLED=true
MIN_PORT=10000
MAX_PORT=20000
```

### Step 2 — Expose your local service

```bash
portal expose --tcp --name myapp localhost:8080
```

Portal registers a lease and receives an allocated port from the relay's range. The output will show the assigned port:

```text
TCP port: relay.example.com:12345
```

### Step 3 — Connect clients

Clients connect directly to the relay host and allocated port:

```text
relay.example.com:12345
```

No special client software is needed — any TCP client works.

## UDP Tunneling

UDP tunneling transports datagrams over a QUIC backhaul. The relay listens on an allocated UDP port and forwards datagrams to your local UDP service.

### Step 1 — Configure the relay

```bash
UDP_ENABLED=true
MIN_PORT=10000
MAX_PORT=20000
```

### Step 2 — Expose your local service

Use `--udp` to enable UDP, and `--udp-addr` to specify the local UDP target address:

```bash
portal expose --udp --udp-addr localhost:19132 --name myapp localhost:8080
```

- `--udp-addr` — the local UDP address that receives relayed datagrams. Defaults to the primary target address when `--udp` is set without `--udp-addr`.
- The primary target (`localhost:8080` above) is still used for any TCP/HTTP traffic on the same lease.

## Minecraft Server Example

This is a complete walkthrough for exposing a Minecraft Java Edition server (`localhost:25565`) to the public internet.

### Relay docker-compose snippet

```yaml
services:
  relay:
    image: ghcr.io/gosuda/portal:latest
    environment:
      TCP_ENABLED: "true"
      MIN_PORT: "10000"
      MAX_PORT: "20000"
    ports:
      - "443:443"
      - "4017:4017"
      - "10000-20000:10000-20000"  # TCP port range
```

<div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 0.75rem 1rem; border-radius: 0.375rem; margin: 1rem 0;">
  <strong>Note:</strong> Docker's port range syntax (<code>10000-20000:10000-20000</code>) creates one mapping per port. Keep ranges reasonably small — large ranges (10 000+ ports) can slow Docker startup.
</div>

### Expose the server

```bash
portal expose --tcp --name minecraft localhost:25565
```

Output:

```text
TCP port: relay.example.com:13742
```

### Connect in Minecraft

In the Minecraft multiplayer screen, add a server with the address:

```text
relay.example.com:13742
```

That's it. The port number will remain the same as long as the tunnel is active and the lease is held by the same identity.

## Combining TCP + UDP

A single lease can carry both a raw TCP port and a UDP relay simultaneously. This is useful for servers that use both protocols — for example, a game server that streams data over TCP and sends position updates over UDP.

```bash
portal expose --tcp --udp --udp-addr localhost:19132 localhost:25565
```

This registers one lease that gets:
- A dedicated TCP port for `localhost:25565`
- A dedicated UDP port forwarding datagrams to `localhost:19132`

Both ports are drawn from the same `MIN_PORT`–`MAX_PORT` range on the relay.

## Limitations

- **Port range capacity** — the relay can serve at most `MAX_PORT - MIN_PORT + 1` concurrent TCP+UDP leases. Plan the range accordingly.
- **No TLS on raw TCP** — the raw TCP path has no TLS wrapping. Traffic between the relay and connecting clients is unencrypted. Use application-level encryption (e.g. SSH, WireGuard) if the service requires confidentiality.
- **UDP max packet size** — datagrams are capped at **1350 bytes**. Packets larger than this are dropped. Most game protocols fit within this limit, but verify if you use a custom protocol.
- **Flow idle timeout** — UDP flows that have seen no traffic for **30 seconds** are cleaned up on the relay. Long-lived connections should send keepalive packets if they may be idle.
