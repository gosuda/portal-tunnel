---
title: Architecture
description: Portal system architecture, transport model, and protocol details.
priority: P1
---

<script>
import Mermaid from '$lib/components/Mermaid.svelte'

const overviewDiagram = `flowchart TD
    CB[Client Browser]
    ETC[External TCP Client]
    EUC[External UDP Client]

    subgraph Relay["Relay Server"]
        SNI["SNI Router :443"]
        API["API Server / Control Plane"]
        TCP["TCP Port Listener"]
        QUIC["QUIC Datagram Listener"]
    end

    subgraph SDK["SDK / portal-tunnel"]
        RC["Reverse Connect Handler"]
        TLS["Tenant TLS Terminator"]
        SDKUDP["UDP Forwarder"]
    end

    LS["Local Service"]
    LU["Local UDP Service"]

    CB -- TLS ClientHello --> SNI
    SNI -- SNI route + 0x02 marker --> RC
    RC --> TLS --> LS

    ETC -- raw TCP --> TCP
    TCP -- 0x01 marker + bridge --> RC

    EUC -- UDP packet --> QUIC
    QUIC -- QUIC DATAGRAM frame --> SDKUDP --> LU

    SDK -- POST /sdk/register, GET /sdk/connect --> API`

const tlsStreamDiagram = `sequenceDiagram
    participant SDK as SDK / portal-tunnel
    participant Relay as Relay Server
    participant Client as Client Browser

    SDK->>Relay: POST /sdk/register/challenge
    Relay->>SDK: SIWE challenge message
    SDK->>Relay: POST /sdk/register (signed)
    Relay->>SDK: access_token + lease info

    SDK->>Relay: GET /sdk/connect (HTTP/1.1 hijack)
    Relay->>SDK: connection hijacked, 0x00 keepalives
    Note over Relay: Session queued in per-lease stream ready queue

    Client->>Relay: TLS ClientHello (SNI: name.relay.host)
    Note over Relay: SNI peek, resolve lease, claim reverse session
    Relay->>SDK: write 0x02 (TLS activation marker)
    Note over SDK: Starts tenant TLS handshake locally via keyless signer
    Relay->>Client: bridges raw encrypted bytes bidirectionally
    Note over Client,SDK: End-to-end TLS, relay never sees plaintext`

const tcpPortDiagram = `sequenceDiagram
    participant SDK as SDK / portal-tunnel
    participant Relay as Relay Server
    participant ExtClient as External TCP Client

    SDK->>Relay: POST /sdk/register (tcp_enabled=true, signed SIWE)
    Note over Relay: Validates TCP plane enabled, allocates port from MIN_PORT-MAX_PORT
    Relay->>SDK: tcp_addr + access_token

    SDK->>Relay: GET /sdk/connect (reverse session, HTTP/1.1 hijack)
    Note over Relay: Session queued in per-lease stream ready queue

    ExtClient->>Relay: TCP connect to tcp_addr
    Note over Relay: Accepts connection, claims reverse session
    Relay->>SDK: write 0x01 (raw TCP activation marker)
    Note over SDK: Receives 0x01, passes raw connection without TLS handshake
    Relay->>ExtClient: bridges data bidirectionally (raw TCP)
    Note over ExtClient,SDK: No TLS, pure raw TCP passthrough`

const udpQuicDiagram = `sequenceDiagram
    participant SDK as SDK / portal-tunnel
    participant Relay as Relay Server
    participant UDPClient as External UDP Client

    SDK->>Relay: POST /sdk/register (udp_enabled=true, signed SIWE)
    Note over Relay: Allocates UDP port from MIN_PORT-MAX_PORT
    Relay->>SDK: udp_addr + access_token + sni_port

    SDK->>Relay: QUIC connect to sni_port (ALPN: portal-tunnel, DATAGRAM enabled)
    SDK->>Relay: Send access_token on first QUIC stream
    Note over Relay: Validates token, registers QUIC tunnel for lease

    UDPClient->>Relay: UDP packet to udp_addr
    Note over Relay: Assigns flow ID, wraps in QUIC DATAGRAM frame
    Relay->>SDK: QUIC DATAGRAM frame (flowID + payload)
    Note over SDK: Decodes frame, forwards to local UDP service

    SDK->>Relay: QUIC DATAGRAM frame (flowID + response)
    Relay->>UDPClient: WriteToUDP back to original client address`

const registrationDiagram = `sequenceDiagram
    participant SDK as SDK / portal-tunnel
    participant Relay as Relay Server

    SDK->>Relay: POST /sdk/register/challenge (address)
    Relay->>SDK: SIWE challenge message

    Note over SDK: Signs SIWE message with secp256k1 identity key (personal_sign)

    SDK->>Relay: POST /sdk/register (message, signature, name, tcp_enabled?, udp_enabled?)
    Note over Relay: Validates SIWE signature, checks name availability
    Note over Relay: Creates lease, publishes route at name.relay-host
    Note over Relay: Allocates TCP/UDP ports if requested
    Relay->>SDK: access_token (ES256K JWT) + lease info (tcp_addr?, udp_addr?, sni_port?)`
</script>

<div class="not-prose mb-8 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-950/30 dark:text-blue-300">
  <strong>Advanced Documentation</strong> — This page covers internal architecture details for contributors and advanced users.
</div>

# Architecture

## Overview

Portal publishes local services on public subdomains, optional dedicated TCP ports, and optional UDP ports through a relay.
Backends connect outward to the relay. Stream traffic is routed by SNI, and tenant TLS remains end-to-end between the client and the SDK or tunnel endpoint for the stream path.

High-level path:

```text
Stream client
  -> Relay SNI listener (:443 by default)
  -> Claimed reverse session
  -> SDK / portal-tunnel
  -> Local service

TCP port client
  -> Relay lease TCP port (within configured MIN_PORT-MAX_PORT)
  -> Claimed reverse session (raw TCP, no TLS)
  -> SDK / portal-tunnel
  -> Local service

UDP client
  -> Relay lease UDP port (within configured MIN_PORT-MAX_PORT)
  -> Internal QUIC tunnel
  -> SDK / portal-tunnel
  -> Local UDP service
```

<Mermaid code={overviewDiagram} />

## Architecture Invariants

### Transport and Routing

- Raw TCP reverse-connect is the canonical stream transport.
- Do not introduce websocket or legacy compatibility paths by default.
- Derive lease hostnames from the full normalized `PORTAL_URL` host, not from apex extraction.
- Preserve explicit root-host fallback through SNI no-route handling to the admin/API listener.
- Stream ingress is TLS-only. UDP exposure, when enabled, is raw UDP.

### TLS and Identity

- Relay terminates admin/API TLS on the root host and exposes `/v1/sign` for tenant-side keyless signing.
- Control-plane HTTP (`/sdk/*`), reverse-session establishment (`/sdk/connect`), and tenant TLS are separate connections with different trust boundaries.
- Relay API TLS, SDK relay-client TLS, SDK tenant-server TLS, and QUIC tunnel TLS are distinct configs even when they reuse the same relay certificate material.
- Relay does not terminate tenant TLS. It peeks ClientHello for SNI and bridges raw encrypted bytes after routing.
- SDK/tunnel endpoints terminate tenant TLS locally with a keyless-backed signer that calls the relay.
- In keyless TLS, the relay performs certificate private-key signing through `/v1/sign`, but the SDK/tunnel endpoint still runs the TLS server handshake and derives tenant TLS session keys locally.
- `/sdk/connect`, `/sdk/renew`, and `/sdk/unregister` are authorized by lease existence plus a relay-issued lease access token.
- `/sdk/register` is authenticated by a SIWE challenge/response flow using the SDK identity secp256k1 key. On success, the relay issues a lease-scoped ES256K JWT access token signed by the relay identity key and used for the rest of the lease lifecycle.
- Relay URLs must use `https://`.
- HTTP/2 stays disabled on the admin/API TLS listener because `/sdk/connect` depends on HTTP/1.1 hijacking semantics.
- WireGuard, when enabled, is relay-to-relay overlay transport only. It carries multi-hop relay forwarding and overlay discovery, but it is not used for direct tenant TLS termination, public UDP ingress, or `/sdk/*` control-plane traffic.

### Reverse Session Protocol

- SNI wildcard matching is one level only. `*.parent.example.com` matches `foo.parent.example.com`, not deeper labels.
- Reverse TCP marker bytes remain protocol state:
  - `0x00` = idle keepalive
  - `0x01` = raw TCP activation (non-TLS port routing)
  - `0x02` = TLS passthrough activation
- `/sdk/connect` remains HTTP/1.1 only.

### JSON and Shared Contract

- All JSON control-plane responses use `APIEnvelope`: `{ ok, data?, error? }`.
- JSON handlers should write responses through the shared API helpers.
- `types/` is reserved for shared wire/public types and cross-package constants only.
- Shared control-plane and public route constants belong in `types/paths.go`.
- Relay-local frontend asset filenames stay local to `cmd/relay-server`.
- Do not import `portal` from `cmd/*` or `sdk` just to reach shared DTOs or constants.

### Operational Constraints

- For non-localhost deployments, relay TLS can run from manual certificate files in the relay `IDENTITY_PATH` directory or from managed ACME.
- When managed ACME is enabled, supported DNS providers are `cloudflare`, `gcloud`, and `route53`.
- ENS gasless automation reuses `ACME_DNS_PROVIDER` for DNSSEC and ENS TXT sync.
- Relay stores its state under `IDENTITY_PATH`, including `identity.json`, `admin_settings.json`, and certificate material. Tunnel and demo-app identities still use `IDENTITY_PATH` / `--identity-path` as a direct JSON file path.
- Managed non-localhost ACME keeps both root and wildcard DNS A records in sync.
- Relay certificate material lives under `IDENTITY_PATH` as `fullchain.pem` and `privatekey.pem`.
- Localhost uses the development certificate path instead of public managed/manual certificate setup.

## Connection Model

Portal has three distinct network roles:

- **Control-plane HTTP requests**
  - `POST /sdk/register/challenge`
  - `POST /sdk/register`
  - `POST /sdk/renew`
  - `POST /sdk/unregister`
  - `GET /sdk/domain`
- **Reverse session connection**
  - `GET /sdk/connect`
  - HTTP/1.1 only
  - hijacked into a long-lived raw TCP session
  - starts idle in the per-lease stream ready queue, then becomes the tenant data path when claimed
- **Internal datagram tunnel**
  - QUIC to the relay URL host plus the relay-advertised `sni_port` from `POST /sdk/register` with ALPN `portal-tunnel`
  - authenticated by a first-stream control message carrying `access_token`
  - carries relay-to-SDK/tunnel datagram traffic only

That distinction matters because `/sdk/connect` stops being ordinary HTTP once hijacked, while the UDP backhaul is a separate internal QUIC carrier.

## Package Layout

The relay runtime lives in `portal/` (server, route table, transport runtimes, ACME, keyless, auth, discovery, WireGuard overlay, policy).
The SDK client library lives in `sdk/` (listener, exposure, relay API client, MITM self-probe, transport clients).
CLI entry points live in `cmd/relay-server` and `cmd/portal-tunnel`; they import `portal/` and `sdk/` respectively but never each other.
Shared wire types, API envelope, error codes, path constants, and transport frame codec live in `types/`.

## Transport Model

### Raw reverse transport (TLS only)

1. SDK/tunnel registers one lease per relay through `POST /sdk/register/challenge` followed by `POST /sdk/register`.
2. SDK opens one or more reverse sessions per registered lease with `GET /sdk/connect`.
3. Each relay hijacks `/sdk/connect` requests and places the connection in the per-lease stream ready queue.
4. While idle, the relay writes `0x00` keepalive markers.
5. A stream client connects to the relay SNI listener.
6. Relay extracts SNI from ClientHello, resolves a lease, and waits up to `ClaimTimeout` for one reverse session from that lease stream queue.
7. Relay writes `0x02` to activate the claimed session.
8. SDK/tunnel receives `0x02`, starts tenant TLS locally using the relay-backed keyless signer, and the relay bridges raw encrypted bytes end-to-end.

Result: the relay decides routing, but tenant TLS termination still happens at the SDK/tunnel side.

<Mermaid code={tlsStreamDiagram} />

### Tenant TLS Self-Probe Detection

1. After a real tenant connection begins I/O, the SDK may start one asynchronous self-probe for that listener if no probe is in flight and the 30-second cooldown has expired.
2. The SDK opens a new TLS connection to its own public URL using the same tenant-facing TLS characteristics as normal traffic.
3. The probe client exports TLS keying material (`ExportKeyingMaterial`) from that probe connection and stores it under a random nonce.
4. The first encrypted probe payload is `16-byte nonce + random padding`; there is no fixed probe magic or dedicated ALPN.
5. When the probe connection comes back through the relay and reaches the SDK-side tenant TLS terminator, the SDK peeks only the first 16 encrypted application bytes while a probe is pending.
6. If those bytes match a pending nonce, the SDK exports keying material on the server side and compares it with the client-side exporter value.
7. Matching exporter values mean the probe observed passthrough for that connection. A mismatch is logged as suspected relay-side TLS termination. A timeout is logged as probe failure, not proof of MITM.

Result: this is a detect-only signal by default. It raises the cost of adaptive relay-side TLS termination, but it does not prove passthrough for every user connection. Callers that need stricter behavior can opt into relay banning.

### TCP Port Transport (non-TLS)

1. SDK/tunnel requests a register challenge with `tcp_enabled=true`, signs the returned SIWE message, and completes registration.
2. Relay validates that the TCP port plane is enabled, allocates a TCP port, and creates a per-lease TCP listener.
3. Registration response includes `tcp_addr` (public TCP endpoint).
4. An external TCP client connects to `tcp_addr`.
5. The relay accepts the connection, claims a reverse session from the lease stream queue, and writes `0x01` (raw TCP activation marker).
6. SDK-side receives `0x01` and passes the raw connection directly without TLS handshake.
7. Data is copied bidirectionally between the external client and the reverse session.

Result: the relay allocates a dedicated TCP port per lease and bridges raw TCP without TLS. This is ideal for non-TLS protocols like Minecraft, game servers, or any raw TCP service.

<Mermaid code={tcpPortDiagram} />

### UDP/QUIC Datagram Transport

1. SDK/tunnel requests a register challenge with `udp_enabled=true`, signs the returned SIWE message, and completes registration.
2. Relay validates that the datagram plane is enabled, allocates a UDP port, and creates a per-lease datagram runtime.
3. Registration response includes `udp_addr`, `access_token`, and `sni_port`. The SDK dials QUIC to the relay on `sni_port`.
4. SDK opens a QUIC connection with ALPN `portal-tunnel` and DATAGRAM support enabled.
5. Authentication: SDK sends `{access_token}` JSON on the first QUIC stream; relay validates before accepting the tunnel.
6. External UDP client sends a packet to `udp_addr` -> relay assigns a flow ID -> QUIC DATAGRAM frame to SDK.
7. SDK-side decodes frames and delivers to local UDP target.
8. Return path: local response -> SDK -> QUIC DATAGRAM -> relay -> `WriteToUDP` to the original client.

Result: raw public UDP exposure with an internal QUIC datagram backhaul. UDP and TCP port allocations are independent from the same `MIN_PORT-MAX_PORT` range.

<Mermaid code={udpQuicDiagram} />

## WireGuard Overlay and Discovery

- Discovery bootstraps from public HTTPS relay URLs, then expands through relay-to-relay `/discovery` polling and periodic self-announces to bootstrap relays through `/discovery/announce`.
- SDK exposures consume relay discovery results to choose relays, but they do not announce themselves and do not serve `/discovery`.
- Discovery descriptors are signed relay self-descriptions. They bind relay routing metadata such as `api_https_addr`, `supports_overlay`, `wireguard_public_key`, and `wireguard_port` to the relay identity. Lease access tokens remain separate and authorize tenant lease operations only.
- `/discovery/announce` accepts only signed relay descriptors. Loopback or localhost relay descriptors are rejected because they cannot join the public discovery mesh.
- The overlay peer API is plain HTTP on the WireGuard network, not public Internet HTTP. It serves the same discovery payload shape used by public `/discovery`.
- Overlay failure affects inter-relay discovery, mesh synchronization, and multi-hop relay forwarding. Direct tenant TLS routing, keyless TLS, register/renew/connect, and public UDP ingress do not depend on the WireGuard transport path.

### Local multi-hop test harness

`portal/multihop_local_test.go` verifies the multi-hop relay path inside one `go test` process. It starts local relay servers on `127.0.0.1:0`, seeds signed local discovery descriptors, and uses test fakes only for the WireGuard transport layer.

Use `make test-local-multihop` for the focused local harness. The same tests are also included in `make test` through the `./portal/...` package set. Use `go test ./portal ./sdk` when checking the narrower portal and SDK interaction without the full repository test suite.

The harness exercises SDK expose/register logic, `/sdk/hop`, `RelaySet`, signed descriptors, route registration, SNI ingress, hop token matching, and `bridgeLeaseConn`. It intentionally excludes public DNS, ACME provider side effects, public registry bootstrap, and real WireGuard devices. `localRelaySpec` provides relay-level server and descriptor mutation hooks for future policy tests, and the fake overlay records synced peers so fake hop streams only open after the `/sdk/hop` overlay sync path has run.

## Control Plane Flow

### 1. Register

- `POST /sdk/register/challenge` then `POST /sdk/register`.
- Caller signs the returned SIWE message with the identity secp256k1 key (`personal_sign`).
- `name` must be a valid single DNS label; the relay publishes the lease at `<name>.<root host>`.
- Registration reserves the hostname and publishes the route immediately; if no reverse session is ready yet, inbound SNI claims wait up to `ClaimTimeout`.
- On success, the relay issues a lease-scoped ES256K JWT access token signed by the relay identity key, used for the rest of the lease lifecycle.
- UDP registration requires server `UDP_ENABLED=true`, a valid `MIN_PORT/MAX_PORT` range, and admin enablement. Failures: `udp_disabled` (403), `udp_capacity_exceeded` (503), `udp_port_exhausted` (503).
- TCP port registration has equivalent three-condition gating. Failures: `tcp_port_disabled` (403), `tcp_port_capacity_exceeded` (503), `tcp_port_exhausted` (503).
- `PORTAL_URL` is normalized to its host component only; path/query segments are ignored for routing.

<Mermaid code={registrationDiagram} />

### 2. Reverse Connect

- `GET /sdk/connect` (HTTP/1.1 only, `X-Portal-Access-Token` header).
- Relay validates: lease exists and is not expired; access token signature, issuer, audience, identity, and expiry are all valid.
- After claim, relay writes `0x02` before switching the session into tenant TLS passthrough.
- After hijack, the connection becomes a broker-managed reverse session.

### 3. Renew

- `POST /sdk/renew` with `access_token`. Extends lease TTL and returns a refreshed token.

### 4. Unregister

- `POST /sdk/unregister` with `access_token`. Removes the lease, routes, and ready reverse sessions.

## Routing Behavior

Route lookup order:

1. Exact hostname match
2. Single-label wildcard match (`*.example.com`)
3. Root-host fallback to the admin/API listener

Notes:

- Wildcards are one level only.
- The exact root host is never served by the wildcard route.
- For non-apex `PORTAL_URL` values such as `https://portal.example.com:8443/admin`, a lease named `demo` is published at `demo.portal.example.com`.

## Admin and Frontend Surface

The admin surface is intentionally small: an HTML index, one JSON snapshot endpoint, and a small set of admin action/auth routes. Route paths are enumerated in `types/paths.go` and `cmd/relay-server`.

## Keyless TLS Trust Model

The relay signs handshake digests via `/v1/sign` but never receives tenant TLS traffic secrets. The SDK/tunnel endpoint runs the full TLS server handshake and derives session keys locally. Relay control-plane TLS and reverse-session setup terminate on the relay's admin/API listener and are not protected by the tenant keyless path.

## Design Properties

- Reverse-only backend connectivity
- One canonical raw TCP reverse transport
- Dedicated TCP port allocation for non-TLS services with raw TCP bridging
- Raw public UDP exposure with an internal QUIC datagram backhaul
- Optional WireGuard relay overlay for relay discovery, peer synchronization, and multi-hop relay forwarding
- SNI-based routing with root-host fallback
- End-to-end tenant TLS with relay-backed keyless signing
- Traffic-triggered detect-only MITM self-probing for probable relay-side TLS termination
- SIWE identity proof for registration plus relay-issued ES256K JWT access tokens for the lease lifecycle
- Lease-local stream and datagram ownership through per-lease transport runtimes
- Optional QUIC/UDP datagram transport coexisting with TCP on the same lease
- Per-lease UDP and TCP port allocation with sticky name-based reservation
- QUIC tunnel authentication via control stream (`access_token`)
