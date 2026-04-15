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

## MITM Self-Probe

`portal expose` runs an asynchronous TLS passthrough self-probe after real tenant traffic starts. The SDK connects to its own public hostname, exports TLS keying material from the client side, recognizes the returning probe after SDK-side TLS termination, and compares exporter values.

Matching exporter values mean the sampled connection preserved passthrough. A mismatch is treated as suspected relay-side TLS termination. By default, `portal expose` bans that relay; use `--ban-mitm=false` for warning-only behavior.

## Relay Visibility

| Relays can see | Relays cannot see |
|---|---|
| Source IP and timing metadata | HTTP headers or body |
| Tunnel hostname/SNI | Tenant TLS session keys |
| Traffic volume and connection duration | Application payload on the stream path |
| Requested TCP/UDP transport metadata | Local service plaintext on the tenant TLS stream path |
| Raw TCP/UDP payloads when the application protocol is unencrypted | Application-level encrypted raw TCP/UDP payloads |

Raw TCP and UDP port transports do not add tenant TLS. Use application-level encryption for those modes when confidentiality matters.

## Identity

Registration uses a SIWE challenge signed by the SDK's secp256k1 identity key. The relay then issues a lease-scoped ES256K access token used by renew, unregister, reverse connect, and QUIC datagram authentication.

## Next Steps

- [Architecture](/architecture) - deep dive into Portal's internal design
- [Self-Hosting](/self-hosting) - run your own relay server
