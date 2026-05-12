---
title: TCP/UDP Tunneling
description: Tunnel raw TCP and UDP services like game servers through Portal.
---

# TCP/UDP Tunneling

Portal supports dedicated raw TCP and UDP relay modes in addition to the default
HTTPS stream mode. Use these modes for services that need a public port instead
of a browser HTTPS hostname.

## Overview

The default stream path is best for web services:

```bash
portal expose 3000
```

For protocols that do not fit a public HTTPS URL, use one of the port modes:

- **Dedicated raw TCP**: allocates a public TCP port on the relay and bridges raw
  TCP to your local service.
- **UDP relay**: allocates a public UDP port on the relay and carries datagrams
  over the tunnel backhaul to your local UDP service.

Both modes require the relay server to have a port range configured and the
matching transport enabled.

## Relay Configuration

Enable TCP and UDP transports on your relay with these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TCP_ENABLED` | `false` | Enable raw TCP port allocation |
| `UDP_ENABLED` | `false` | Enable UDP/QUIC datagram transport |
| `MIN_PORT` | `0` | Inclusive minimum of the port allocation range; `0` disables allocation |
| `MAX_PORT` | `0` | Inclusive maximum of the port allocation range; `0` disables allocation |

`MIN_PORT` and `MAX_PORT` are shared by TCP and UDP. The protocols are
independent, so the same numeric port can be used by one TCP lease and one UDP
lease at the same time.

Your firewall or cloud security group must allow inbound traffic on the exposed
range for each protocol you enable.

## Dedicated Raw TCP

Raw TCP mode allocates a public TCP port on the relay. Incoming connections to
that port are bridged to your local TCP target.

Configure the relay:

```bash
TCP_ENABLED=true
MIN_PORT=10000
MAX_PORT=20000
```

Expose your local service:

```bash
portal expose --tcp --name myapp localhost:8080
```

The relay returns an assigned TCP address:

```text
TCP port: relay.example.com:12345
```

Clients connect directly to that address:

```text
relay.example.com:12345
```

No Portal client is needed on the connecting side. Any TCP client can connect.
Raw TCP mode does not add TLS, so use application-level encryption if the
protocol needs confidentiality.

## UDP Relay

UDP mode allocates a public UDP port on the relay. Datagrams are carried over a
QUIC backhaul between the relay and the tunnel process, then forwarded to your
local UDP target.

Configure the relay:

```bash
UDP_ENABLED=true
MIN_PORT=10000
MAX_PORT=20000
```

Expose your local service:

```bash
portal expose --udp --udp-addr localhost:19132 --name myapp localhost:8080
```

`--udp-addr` is the local UDP address that receives relayed datagrams. When it is
omitted, Portal uses the primary target address. The primary positional target
is still used for stream traffic on the same lease.

## Minecraft Server Example

This exposes a Minecraft Java Edition server running on `localhost:25565`.

Relay docker-compose snippet:

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
      - "10000-20000:10000-20000"
```

Docker's port range syntax creates one mapping per port. Keep ranges reasonably
small because very large ranges can slow Docker startup.

Expose the server:

```bash
portal expose --tcp --name minecraft localhost:25565
```

Output:

```text
TCP port: relay.example.com:13742
```

In Minecraft, add a server with this address:

```text
relay.example.com:13742
```

The assigned port remains stable while the lease is active and held by the same
identity.

## Combining TCP And UDP

A single lease can carry both a raw TCP port and a UDP relay:

```bash
portal expose --tcp --udp --udp-addr localhost:19132 localhost:25565
```

This registers one lease with:

- a dedicated TCP port for `localhost:25565`
- a dedicated UDP port forwarding datagrams to `localhost:19132`

Both ports are drawn from the same `MIN_PORT` to `MAX_PORT` range on the relay.

## Limitations

- **Port range capacity**: the relay can serve at most
  `MAX_PORT - MIN_PORT + 1` concurrent TCP leases and the same number of UDP
  leases. Plan the range accordingly.
- **No TLS on raw TCP**: raw TCP mode does not add TLS. Use application-level
  encryption when the service requires confidentiality.
- **UDP max packet size**: datagrams are capped at 1350 bytes. Larger packets
  are dropped.
- **Flow idle timeout**: UDP flows with no traffic for 30 seconds are cleaned up
  on the relay. Long-lived protocols should send keepalive packets if they may
  be idle.
