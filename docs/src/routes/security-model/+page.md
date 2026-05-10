---
title: Security Model
description: How Portal keeps tenant traffic opaque to relay operators.
---

# Security Model

Portal is designed so relay operators do not receive tenant traffic plaintext.

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

## Keyless Signing

For relay-hosted names, the SDK builds a tenant-facing TLS server config backed by the relay's `/v1/sign` endpoint. The relay signs handshake digests with its certificate key, but it does not receive the negotiated tenant TLS session keys.

Relay API TLS is separate from tenant TLS:

- Relay API HTTPS protects `/sdk/*`, `/discovery`, `/admin`, installers, and `/v1/sign`.
- Tenant TLS protects end-user traffic for lease hostnames.
- The internal QUIC datagram backhaul uses `SNI_PORT/udp` with ALPN `portal-tunnel`.

## Tunnel ECH

For default stream leases, the SDK derives an opaque route hostname from the tunnel identity private key. The relay still receives the lease identity name and can derive the public fallback hostname so it can validate plaintext-SNI fallback routing and manage DNS automation. The relay stores the route hostname for ECH routing and a validated hash of the public fallback hostname. When DNS automation is enabled, the relay also keeps the public hostname needed to publish and delete its HTTPS `ech` record.

ECH-capable clients can use the opaque route hostname as the outer SNI while the real tenant SNI stays inside the ECH-protected ClientHello handled by the SDK. For multi-hop stream routes, the entry relay gets the opaque route hostname for ECH and the public hostname needed to validate the plaintext-SNI fallback hash and manage DNS automation. After the entry relay chooses the route, the remaining hops continue to use hop tokens and passthrough forwarding.

When `ACME_DNS_PROVIDER` is configured, Portal publishes DNS HTTPS records with the `ech` parameter for the relay root and stream lease public hostnames. Without a DNS provider, operators must distribute the logged ECHConfigList through DNS HTTPS/SVCB or another ECH-capable bootstrap. Without that distribution, ordinary clients keep using the public hostname SNI and the relay routes them through the existing plaintext-SNI fallback.

Legacy clients and raw TCP/UDP transports still use the legacy hostname registration path. On those paths the relay control plane receives the lease hostname and can expose it to admin views.

## MITM Self-Probe

`portal expose` runs an asynchronous TLS passthrough self-probe after real tenant traffic starts. The SDK connects to its own public hostname, exports TLS keying material from the client side, recognizes the returning probe after SDK-side TLS termination, and compares exporter values.

Matching exporter values mean the sampled connection preserved passthrough. A mismatch is treated as suspected relay-side TLS termination. By default, `portal expose` bans that relay; use `--ban-mitm=false` for warning-only behavior.

## Relay Visibility

| Relays can see | Relays cannot see |
|---|---|
| Source IP and timing metadata | HTTP headers or body |
| Lease identity/public hostname, including SNI on the plaintext-SNI fallback path | Tenant TLS session keys |
| Opaque route hostnames on the ECH path | ECH-protected inner SNI when clients use the distributed ECHConfigList |
| Traffic volume and connection duration | Application payload on the stream path |
| Requested TCP/UDP transport metadata | Local service plaintext on the tenant TLS stream path |
| Raw TCP/UDP payloads when the application protocol is unencrypted | Application-level encrypted raw TCP/UDP payloads |

Raw TCP and UDP port transports do not add tenant TLS. Use application-level encryption for those modes when confidentiality matters.

## Identity

Registration uses a SIWE challenge signed by the SDK's secp256k1 identity key. The relay then issues a lease-scoped ES256K access token used by renew, unregister, reverse connect, and QUIC datagram authentication.

## Next Steps

- [Architecture](/architecture) - deep dive into Portal's internal design
- [Self-Hosting](/self-hosting) - run your own relay server
