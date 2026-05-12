---
title: What is Portal?
description: An introduction to Portal, a permissionless localhost tunnel and public relay system.
---

# What is Portal?

Portal is an open-source tunnel system for publishing local services through
public relay servers. It is built around one boundary: **relays provide
transport, while your tunnel process owns the endpoint behavior**.

That means the normal HTTPS stream path does not work like a hosted reverse
proxy. The relay routes by SNI and forwards the connection. Tenant TLS
terminates in the tunnel process on your machine, so the relay does not receive
tenant plaintext or session keys.

## Core Properties

- **Permissionless**: no SaaS account or API key is required.
- **Trustless stream path**: tenant TLS terminates locally, not at the relay.
- **Mode-per-service transport**: use HTTPS stream, routed HTTP, raw TCP, or UDP
  depending on the service.
- **Self-hostable relays**: use the public registry, explicit relay URLs, or your
  own relay.
- **Relay pools and multi-hop**: keep multiple relays connected or route through
  an ordered relay chain.
- **Local identity**: lease ownership is proven with a locally stored secp256k1
  identity and challenge signing.

## The Mental Model

```text
Public client
  -> Relay transport and routing
  -> Tunnel process on your machine
  -> Local service
```

The relay decides where traffic should go. The tunnel process decides what the
traffic means.

For the default stream path, the tunnel process accepts the connection as a TLS
server and then proxies bytes to your local target. For routed HTTP mode, the
tunnel process runs an HTTP reverse proxy and can apply HTTP-specific behavior.
For raw TCP and UDP, the relay allocates public transport endpoints and forwards
traffic to the tunnel process.

## Transport Modes

| Mode | Example | Best for |
|------|---------|----------|
| Default HTTPS stream | `portal expose 3000` | Web apps, APIs, WebSockets, gRPC over HTTP |
| Routed HTTP | `portal expose --http-route /api=3001 --http-route /=5173` | Multiple local HTTP services behind one URL |
| Dedicated raw TCP | `portal expose localhost:25565 --tcp` | Minecraft, game servers, custom TCP protocols |
| UDP relay | `portal expose 8080 --udp --udp-addr 19132` | UDP game servers and datagram protocols |

## When to Use Portal

| Use case | Example |
|----------|---------|
| Share a dev server | Show a local branch to a teammate |
| Webhook development | Receive Stripe, GitHub, or Discord webhooks locally |
| Client demos | Publish a temporary public URL for a staging app |
| Multi-service app demos | Mount frontend and API services under one public URL |
| Home servers | Expose a Minecraft server through a relay TCP port |
| Edge devices | Reach a device behind NAT without opening inbound ports |

## What Portal Does Not Promise

Portal's default stream mode intentionally prevents the relay from controlling
user HTTP responses. That is good for the trust model, but it means a public
multi-tenant relay should not put arbitrary user tunnels under a brand domain
that also carries first-party SEO value. Use a separate tunnel domain for shared
wildcard leases.

## Next Steps

- [Getting Started](/getting-started): install the CLI and expose your first app
- [Concepts](/concepts): understand the trustless relay and transport model
- [CLI Reference](/cli-reference): commands, flags, and examples
