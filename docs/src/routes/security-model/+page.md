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

For relay-hosted names, the SDK builds a tenant-facing TLS server config backed by the relay's `/v1/sign` endpoint. The relay signs handshake digests with a wildcard-only tenant key that is distinct from the relay API key, but it does not receive the negotiated tenant TLS session keys. The SDK obtains the corresponding public certificate chain and key ID from `/v1/keyless/materials`.

Relay API TLS is separate from tenant TLS:

- Relay API HTTPS protects `/sdk/*`, `/discovery`, `/api/admin`, installers, and `/v1/sign`.
- Tenant TLS protects end-user traffic for lease hostnames.
- The internal QUIC datagram backhaul uses `SNI_PORT/udp` with ALPN `portal-tunnel`.

## Tunnel ECH

Tunnel ECH is optional and disabled by default. A normal stream tunnel uses its public hostname as the TLS `ServerName`; the relay routes the encrypted TLS stream by plaintext SNI without terminating tenant TLS. ECH adds hostname privacy, not the end-to-end TLS protection itself.

Enable ECH for a CLI tunnel with `portal expose ... --ech` or set `ech = true` in a portal-agent tunnel. For ECH-enabled stream leases, the SDK derives an opaque route hostname and tenant ECH material from the tunnel identity. The relay receives the route hostname, a validated hash of the public fallback hostname, and the ECHConfigList. ECH-capable clients use the opaque route hostname as the outer SNI while the real tenant SNI remains inside the ECH-protected ClientHello handled by the SDK.

ECH-enabled tunnels retain plaintext-SNI fallback routing. This lets clients that do not obtain or use the ECHConfigList connect through the public hostname without weakening tenant TLS passthrough. For multi-hop routes, the entry relay owns ECH and plaintext-SNI selection; later hops continue with hop tokens and passthrough forwarding.

When `ACME_DNS_PROVIDER` is configured, Portal publishes the relay root HTTPS/ECH record. For each ECH-enabled stream lease it also creates or updates the public hostname A record and HTTPS record containing the `ech` parameter. Portal does not create tenant ECH DNS records for the default `ECH=false` mode. It removes tenant A and HTTPS/ECH records when the owning ECH lease is removed and no active replacement requires the hostname. Successful ECH HTTPS operations are not periodically rewritten; failed create, update, and delete operations remain pending for retry. Active ECH hostname A records are updated when Portal observes that the relay public IPv4 has changed.

Without a DNS provider, operators must distribute the ECHConfigList through DNS HTTPS/SVCB or another ECH-capable bootstrap. Until clients obtain that configuration, they continue through the public hostname and plaintext-SNI fallback.

Enabling UDP or a dedicated raw TCP port does not disable tunnel ECH on the
default TLS hostname. The additional raw TCP and UDP endpoints do not themselves
use ECH or add tenant TLS.

## MITM Self-Probe

`portal expose` runs an asynchronous TLS passthrough self-probe after real tenant traffic starts. The SDK connects to its own public hostname, exports TLS keying material from the client side, recognizes the returning probe after SDK-side TLS termination, and compares exporter values.

Matching exporter values mean the sampled connection preserved passthrough. A mismatch is treated as suspected relay-side TLS termination and logged by default; use `--ban-mitm` when suspected TLS termination should ban the relay.

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

Registration uses a SIWE challenge signed by the SDK's secp256k1 identity key. The key is loaded from `identity.json` either as a raw secp256k1 `private_key` or derived from a BIP-39 `mnemonic` and `derivation_path`. The relay then issues a lease-scoped ES256K access token used by renew, unregister, reverse connect, and QUIC datagram authentication.

Relay admin token login and optional local agent wallet login are separate from
lease registration. They do not replace the local tunnel identity used for
registration.

## Next Steps

- [Architecture](/architecture) - deep dive into Portal's internal design
- [Wallet and ENS](/wallet-and-ens) - admin tokens, wallet auth, and ENS gasless DNS import
- [Self-Hosting](/self-hosting) - run your own relay server
