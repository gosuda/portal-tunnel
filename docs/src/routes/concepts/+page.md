---
title: Concepts
description: Understand Portal's relay model, transport modes, and end-to-end TLS design.
---

# Concepts

Portal publishes local services through relay servers. The important design
choice is that the relay is a transport and routing component, not the owner of
your application traffic.

## Relay And Tunnel Responsibilities

The relay owns:

- lease registration and renewal
- public hostname and port routing
- SNI route lookup for the default stream path
- relay discovery and relay-to-relay forwarding
- admin policy such as approval, bans, and transport limits

The tunnel process owns:

- tenant TLS termination for the default HTTPS stream path
- local target proxying
- routed HTTP reverse proxy behavior
- UDP target forwarding
- identity keys and lease signing
- MITM self-probe validation

This split is why Portal can use public relays without giving relay operators
tenant plaintext.

## Default Stream Path

The default command is:

```bash
portal expose 3000
```

The public URL is HTTPS, but the relay does not terminate tenant TLS.

```text
Browser
  -> Relay :443
  -> reverse session
  -> tunnel process TLS server
  -> 127.0.0.1:3000
```

Flow:

1. A browser connects to the relay and sends a TLS ClientHello.
2. The relay reads the SNI hostname and finds the matching lease.
3. The relay claims a waiting reverse session from the tunnel process.
4. The tunnel process performs the tenant TLS handshake locally.
5. The relay may sign handshake digests through `/v1/sign`, but it does not
   receive tenant TLS session keys.
6. After the handshake, the relay forwards encrypted bytes.

## Routed HTTP Mode

Routed HTTP mode mounts one or more local HTTP upstreams behind one public URL:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

This is not relay-side HTTP proxying. The relay still transports the connection.
The tunnel process receives the stream, parses HTTP, and runs the reverse proxy.

Routed HTTP mode can:

- match routes longest-prefix-first
- strip the mounted prefix before proxying
- forward `X-Forwarded-*`
- rewrite matching upstream `Location` redirects
- strip loopback cookie domains
- remap cookie paths to route prefixes

Because HTTP is parsed in the tunnel process, this is the right place for
cooperative HTTP policy such as response headers. It is not a relay-enforced
policy boundary.

## Dedicated Raw TCP

Use raw TCP when clients need a public TCP port instead of a public HTTPS
hostname:

```bash
portal expose localhost:25565 --name minecraft --tcp
```

The relay allocates a port from its configured range and bridges raw TCP to the
tunnel process. This is useful for Minecraft, game servers, and custom TCP
protocols. The raw TCP path does not add TLS; use protocol-level encryption when
needed.

## UDP Relay

Use UDP mode for datagram protocols:

```bash
portal expose localhost:8080 --udp --udp-addr localhost:19132
```

The relay allocates a UDP port and carries datagrams over the tunnel backhaul to
the local UDP target. The positional target is still used for stream traffic;
`--udp-addr` selects the local UDP service.

## Multi-Relay And Multi-Hop

With discovery enabled, Portal starts from the public registry plus explicit
relays, then expands through relay discovery. Explicit relays are always kept
connected separately from the auto-selected relay pool.

Use a fixed ordered route:

```bash
portal expose 3000 --multi-hop https://entry.example.com,https://exit.example.com
```

Or ask Portal to choose one route of a given depth:

```bash
portal expose 3000 --multi-hop-depth 3
```

Multi-hop currently applies to the default SNI TLS stream transport. It is not
combined with UDP or dedicated raw TCP port mode.

## MITM Self-Probe

Portal runs a TLS passthrough self-probe after real stream traffic starts:

1. The tunnel opens a client connection to its own public URL.
2. The tunnel also receives that connection as the tenant TLS server.
3. Both controlled ends export TLS keying material.
4. Matching exporter values indicate passthrough for that sampled connection.
5. A mismatch is treated as suspected relay-side TLS termination.

By default, `portal expose` bans a relay when the self-probe detects
termination. Use `--ban-mitm=false` for warning-only behavior.

The probe is a detection signal, not a mathematical proof for every future
connection. It raises the cost of relay-side termination while preserving the
transport model.

## Identity And Lease Authentication

On first run, Portal creates a local secp256k1 identity at `identity.json` unless
you pass another `--identity-path`.

Lease registration uses challenge signing. After registration, the relay issues
a lease-scoped access token used for renew, unregister, reverse connect, and
datagram authentication.

Reusing the same identity path keeps the same tunnel identity across runs.

## Domain Boundary

The default stream path prevents the relay from safely injecting `robots.txt`,
`noindex`, or arbitrary HTTP headers into user responses. That is a feature of
the trust model, but it also means public multi-tenant relays should use a
separate wildcard tunnel domain instead of a brand or docs domain.

## Next Steps

- [Getting Started](/getting-started): run your first tunnel
- [CLI Reference](/cli-reference): command and flag details
- [Architecture](/architecture): protocol-level design notes
