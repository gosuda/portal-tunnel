---
title: Concepts
description: Understand Portal's relay model, transport architecture, IVNP-backed overlay networking, and end-to-end TLS design.
---

# Concepts

Portal publishes local services through relay servers. The foundational design
choice is that the relay is a transport and routing component, not the owner of
your application traffic.

For a high-level capability matrix across all Portal interfaces, see the
**[Feature Inventory](/features)**.

---

## Relay And Tunnel Responsibilities

Portal establishes a strict separation of concerns between public relays and the
local tunnel process running on your machine:

| Component | Responsibilities |
| :--- | :--- |
| **Relay** | Lease registration and renewals<br/>Public hostname and port routing<br/>SNI route lookup for HTTPS streams<br/>Public relay discovery and gossip<br/>Relay policy enforcement (admission budgets, bans, rate limits) |
| **Tunnel Process** | Tenant TLS termination for default HTTPS exposures<br/>Local target proxying<br/>Routed HTTP reverse proxy behavior & path matching<br/>Local UDP and TCP forwarding<br/>Identity key management & lease signing<br/>Active MITM self-probe validation |

For uncached HTTPS tunnels, this split ensures that client plaintext and session
keys remain exclusively at your local endpoint. Opt-in `--serve --cache`
explicitly permits selected relays to store static files and terminate browser
TLS; see [the cache trust boundary](/security-model#opt-in-static-cache).

---

## Default Stream Path

The standard exposure command is:

```bash
portal expose 3000
```

The resulting public URL is standard HTTPS, but the relay **does not** terminate tenant TLS.

```text
Browser
  -> Relay :443
  -> reverse session
  -> tunnel process TLS server
  -> 127.0.0.1:3000
```

1. **ClientHello**: A browser connects to the relay and sends a TLS ClientHello.
2. **SNI Routing**: The relay reads the SNI hostname, identifies the matching lease, and claims a waiting reverse session from the tunnel process.
3. **Local Handshake**: The tunnel process completes the tenant TLS handshake locally.
4. **Keyless Signing**: For relay-hosted wildcard domains, the tunnel obtains transcript signatures from the relay via `/v1/sign`. The relay never receives session keys.
5. **Ciphertext Forwarding**: After the handshake completes, the relay forwards raw encrypted bytes bidirectionally without access to plaintext.

---

<h2 id="ivnp-backed-overlay-networking">IVNP-backed overlay networking</h2>

Portal can expose a service through a public ingress without owning the network
path behind that ingress. **Portal selects and authorizes endpoints. IVNP owns
the network path between them.** This separates public service identity and
access policy from the routers and tunnels used to reach that service.

| Owner | Responsibilities |
| :--- | :--- |
| **Portal** | Select and authorize the public ingress and overlay gateway; own identity, lease policy, and delegated reverse capability |
| **IVNP** | Construct the gateway-to-ingress path, including routers, tunnels, and internal hop ordering |
| **Tunnel / SDK** | Consume the same generic reverse endpoint and forward streams to the local service |

```text
Direct (default):
Public client -> Portal ingress -> Tunnel / SDK -> Local service

Overlay (opt-in):
Public client
  -> Portal ingress
  -> IVNP overlay network (opaque internal path)
  -> Overlay gateway
  -> Tunnel / SDK
  -> Local service
```

Reverse connections are opened outward by the tunnel, either to the ingress directly
or to a gateway that reaches the ingress through IVNP. The overlay path can span
multiple internal routers opaque to Portal. Portal does not construct a relay chain
or store IVNP topology in discovery or leases.

```bash
portal expose 3000 --overlay
```

`--overlay` prefers an available overlay gateway. Direct reverse transport remains
the default and fallback; the lease and SDK-facing reverse-endpoint contract stay
identical. See [the architecture and protocol flow](/architecture#ivnp-backed-overlay-networking).

---

## Routed HTTP Mode

Routed HTTP mode mounts multiple local HTTP upstreams behind one public URL:

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

The relay still acts strictly as a transport pipe; the local tunnel process
receives the stream, parses HTTP, and executes reverse proxy logic:

- Matches routes longest-prefix-first.
- Strips mounted route prefixes before proxying to upstreams.
- Injects standard forwarding headers (`X-Forwarded-Host`, `X-Forwarded-Proto: https`).
- Preserves the client's `Host` header for all upstreams.
- Rewrites matching upstream `Location` redirects and remaps cookie paths.

### In-Flow x402 Payments

Routed HTTP mode also integrates native micropayments. By attaching pricing to an
HTTP route and providing `--x402-pay-to`:

```bash
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...
```

The tunnel automatically serves `/x402/client.js` and `/x402/prepare` on the
same public origin. Frontends can import `/x402/client.js` to prompt browser
wallets for gasless Sui USDC signatures without external redirects. Native
clients consume `/x402/prepare` directly and supply `X-PAYMENT`.

---

## Dedicated Raw TCP

For services that require a dedicated public TCP port rather than an HTTPS hostname:

```bash
portal expose localhost:25565 --name minecraft --tcp
```

The relay allocates a port from its configured range (`MIN_PORT`-`MAX_PORT`) and
bridges raw TCP streams directly to the tunnel. This path performs no TLS termination;
applications should supply their own protocol-level security.

---

## UDP Relay

For real-time datagram protocols:

```bash
portal expose localhost:8080 --udp --udp-addr localhost:19132
```

The relay allocates a public UDP port and multiplexes incoming datagrams over a
QUIC tunnel backhaul to the local UDP target specified by `--udp-addr`.

---

<h2 id="multi-relay-selection">Multi-Relay Selection & Failover</h2>

When discovery is enabled, Portal bootstraps from the official public registry
plus any explicit relay URLs, then expands through peer discovery gossip.

- Explicit relays are always prioritized and connected.
- Auto-discovered relays form an active pool bounded by `--max-active-relays`.
- The exposure remains reachable through surviving relays when one relay fails.

---

## MITM Self-Probe

Portal runs an active TLS passthrough self-probe after stream traffic begins:

1. The tunnel establishes a client connection to its own public URL.
2. The tunnel receives that incoming connection as the tenant TLS server.
3. Both controlled endpoints export TLS keying material (RFC 5705).
4. Matching values verify direct end-to-end passthrough without relay-side termination.
5. A mismatch signals suspected relay-side interception. Passing `--ban-mitm` automatically bans the offending relay.

---

## Identity And Lease Authentication

On first run, Portal creates a local secp256k1 key pair in `identity.json`.

- Lease registration uses Sign-In with Ethereum (EIP-4361) challenge signing.
- After registration, the relay issues a lease-scoped access token for renewals and signing, and a capability token for reverse streams.
- Reusing `identity.json` preserves domain reservations across sessions.

---

## Domain Boundary

Because the default stream mode prevents relays from modifying user HTTP payloads,
a public multi-tenant relay should not host arbitrary user tunnels on its top-level
brand or documentation domain. Relays use dedicated wildcard subdomains to isolate
user content.

---

## Next Steps

- **[Feature Inventory](/features)**: Searchable matrix of capabilities and interface support.
- **[Architecture](/architecture)**: System sequence diagrams and wire protocol specifications.
- **[Security Model](/security-model)**: Deep dive on tenant TLS, keyless signing, and trust boundaries.
- **[CLI Reference](/cli-reference)**: Complete command-line reference and options.
