---
title: Security Model
description: How Portal keeps tenant traffic opaque to relay operators.
---

# Security Model

Ordinary uncached HTTPS tunnels keep tenant traffic opaque to relay operators.
Raw port transports and opt-in static caching have different trust boundaries.

## Opt-in Static Cache

`portal expose --serve ./dist --cache` explicitly permits selected relays to
store the site's files and terminate browser TLS. Cached connections therefore
expose HTTP headers and content to the serving relay. If that connection falls
back to the live origin, it still trusts the relay; browser-to-origin end-to-end
TLS is not restored on an already terminated connection.

Only the identity-bound canonical hostname is cacheable. Friendly hostnames
are reusable, first-come aliases, so they remain live-origin routes and do not
serve retained content after the origin disconnects.

Use explicit `--relays` with `--discovery=false` to choose exactly which relays
receive the files. Cache mode cannot be combined with `--ban-mitm`.
Ordinary uncached HTTPS tunnels retain the tenant TLS path described below.
See [cache configuration](/configuration#static-relay-cache) for expiry and limits.

## Application Access Authentication

`portal expose 3000 --auth siwe` places a SIWE login gate at the local tunnel
HTTP endpoint. `--auth credential` uses Portal-native credentials instead. Those
credentials are signed by a distinct
key derived from the tunnel identity and bind the subject, tunnel identity,
host, and expiry. Redeem URLs place the credential in the URL fragment, then
exchange it at the tunnel endpoint for the same tunnel-local session cookie.
The session cannot outlive the credential.

Credential signing keys, SIWE challenges, session signing keys, cookies,
subjects, and application plaintext remain outside the relay control plane.
SIWE challenges expire after two minutes; signed sessions expire after at most
24 hours.

The auth gate wraps the complete HTTP router, including static files and x402
routes. Portal removes client-supplied `X-Portal-User` and `X-Portal-Auth`
headers before routing and only restores verified values when
`--auth-identity-headers` is enabled. It also consumes the Portal session cookie
at the gate, so upstream applications receive their own cookies but never the
`__Host-portal_access` credential. Application auth cannot be combined with
relay caching or raw TCP/UDP exposure.

API clients may submit the signed credential in
`X-Portal-Access-Credential`. The tunnel validates it on every request and
removes the header before routing, so the upstream never receives the bearer
credential. When a request also carries a Portal session cookie, the explicit
credential header is authoritative; an invalid credential is rejected instead
of falling back to the session.

## Tenant TLS

For the default stream path, the relay only peeks at the TLS ClientHello long enough to read SNI and choose a lease. After that it bridges encrypted bytes over a reverse session.

```text
Client browser
  -> Relay SNI router
  -> Reverse session
  -> SDK tenant TLS terminator
  -> Local service
```

Tenant TLS terminates on the SDK side. The local service receives the decrypted stream from the tunnel process, while the relay only handles routing metadata and ciphertext.

<div id="browser-wasm-transport"></div>

### Browser/WASM transport

For an ordinary uncached exposure, running the SDK in WebAssembly changes the
reverse carrier, not the tenant TLS boundary. The browser connector reaches the
relay through WebSocket and carries reverse connections as yamux streams, but
the encrypted tenant stream still terminates in the SDK runtime. The relay
terminates the outer WebSocket TLS and observes multiplexing metadata, while
tenant HTTP headers, bodies, and session keys remain protected by the normal
tenant TLS path.

Each logical yamux stream is authorized with the current short-lived reverse
capability before the relay can offer it to the lease. Keeping a WebSocket open
does not extend an expired capability's authority to open new streams.

Browser runtimes support HTTPS handler exposure only. Raw TCP, UDP, overlay,
and the native MITM self-probe require socket capabilities that the browser
runtime does not provide.

## Keyless Signing

For relay-hosted names, the SDK terminates tenant TLS with a `keyless_tls` t13server backed by the relay's `/v1/sign` endpoint. The relay signs handshake transcripts with its certificate key, but it does not receive the negotiated tenant TLS session keys.

Relay API TLS is separate from tenant TLS:

- Relay API HTTPS protects `/sdk/*`, `/discovery`, `/api/admin`, installers, and `/v1/sign`.
- Tenant TLS protects end-user traffic for lease hostnames.
- The QUIC datagram backhaul uses the public `PORTAL_URL` port with ALPN `portal-tunnel`; `SNI_PORT` controls the relay's corresponding local UDP listener.

## MITM Self-Probe

`portal expose` runs an asynchronous TLS passthrough self-probe after real tenant traffic starts. The SDK connects to its own public hostname, exports TLS keying material from the client side, recognizes the returning probe after SDK-side TLS termination, and compares exporter values.

Matching exporter values mean the sampled connection preserved passthrough. A mismatch is treated as suspected relay-side TLS termination and logged by default; use `--ban-mitm` when suspected TLS termination should ban the relay.

The probe needs a tenant TLS stack that exports TLS keying material on both sides. The keyless TLS tenant terminator exports TLS 1.3 keying material, so the probe runs against tenant TLS exposures. Exposures started with `--ban-mitm` (or `BAN_MITM`) fail at start with an explicit error if the selected tenant TLS stack cannot export keying material, instead of running without the requested protection.

## Relay Visibility

For ordinary uncached tunnels:

| Relays can see | Relays cannot see |
|---|---|
| Source IP and timing metadata | HTTP headers or body |
| Lease identity/public hostname, including SNI | Tenant TLS session keys |
| Traffic volume and connection duration | Application payload on the stream path |
| Requested TCP/UDP transport metadata | Local service plaintext on the tenant TLS stream path |
| Raw TCP/UDP payloads when the application protocol is unencrypted | Application-level encrypted raw TCP/UDP payloads |

Raw TCP and UDP port transports do not add tenant TLS. Use application-level encryption for those modes when confidentiality matters.

## Identity

Registration uses a SIWE challenge signed by the SDK's secp256k1 identity key. The key is loaded from `identity.json` either as a raw secp256k1 `private_key` or derived from a BIP-39 `mnemonic` and `derivation_path`. The relay then issues a lease-scoped ES256K access token used by renew, unregister, keyless signing, and QUIC datagram authentication, plus a separate reverse-only capability for reverse streams.

Application access login, relay admin token login, and optional local agent
wallet login are separate from lease registration. They do not replace the
local tunnel identity used for registration.

## Next Steps

- [Architecture](/architecture) - deep dive into Portal's internal design
- [Wallet and ENS](/wallet-and-ens) - admin tokens, wallet auth, and ENS gasless DNS import
- [Self-Hosting](/self-hosting) - run your own relay server
