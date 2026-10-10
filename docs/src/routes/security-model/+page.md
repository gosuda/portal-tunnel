---
title: Security Model
description: Tenant TLS guarantees, relay signing authority, and the limits of MITM detection.
---

# Security Model

Portal minimizes relay trust; it does not yet eliminate it.

In the normal uncached HTTPS path, tenant TLS terminates in the local tunnel
process. A relay that forwards this traffic cannot read application plaintext or
derive the tenant session keys from its certificate signing key. A malicious
relay holding that key can still authenticate as a tenant endpoint and actively
terminate TLS. The self-probe adds detection on sampled connections, not a proof
that all connections are safe.

This page defines the supported trust boundaries. For the design rationale,
handshake flow, and browser-delegation context, read
[Building End-to-End TLS Tunnels Without Delegated Credentials](/keyless-tls).
Raw port transports and opt-in static caching have different boundaries below.

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

In normal passthrough operation, credential signing keys, SIWE challenges,
session signing keys, cookies, subjects, and application plaintext remain
outside the relay control plane.
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

For relay-hosted names, the SDK terminates tenant TLS 1.3 with a `keyless_tls`
t13server backed by the relay's `/v1/sign` endpoint. The SDK generates the
ephemeral key material and derives the session keys; the relay supplies
certificate signatures without receiving those traffic secrets.

The signing API requires an authenticated, current public lease. Each request
also carries a short-lived connection binding associated with that lease and
the ClientHello captured on the routed connection. Portal checks the binding's
lease, expiry, and ClientHello hash and consumes it before signing. The signer
constructs a TLS 1.3 `CertificateVerify` signature from the submitted handshake
fields; it does not expose an arbitrary-digest signing endpoint. Portal's
ingress comparison covers the ClientHello, not an independent observation of
every submitted server-side transcript field.

These checks constrain clients of an honest signer. The relay owns both the
certificate private key and the binding registry, so they cannot prevent that
relay from bypassing its own policy. See the
[binding implementation](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/bindings.go)
and [signing endpoint](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/signer.go).

Relay API TLS is separate from tenant TLS:

- Relay API HTTPS protects `/sdk/*`, `/discovery`, `/api/admin`, installers, and `/v1/sign`.
- Tenant TLS protects end-user traffic for lease hostnames.
- The QUIC datagram backhaul uses the public `PORTAL_URL` port with ALPN `portal-tunnel`; `SNI_PORT` controls the relay's corresponding local UDP listener.

<h3 id="local-development-trust">Local development trust</h3>

Public relay endpoints use normal certificate-chain and hostname verification.
For loopback addresses, `localhost`, and `.localhost` names, the SDK instead
bootstraps trust from the chain presented by the contacted endpoint. That
initial fetch skips certificate verification; subsequent connections use the
collected chain. This development convenience is not independent verification
of the relay operator. See the [relay TLS bootstrap](https://github.com/gosuda/portal-tunnel/blob/main/utils/tls.go).

<h2 id="relay-trust-reduction">Relay Trust Reduction</h2>

The following guarantees apply to ordinary uncached tenant TLS with an
uncompromised client and tunnel endpoint.

| Threat or operating condition | Current behavior | Remaining boundary |
|---|---|---|
| Relay follows the forwarding protocol | Tenant TLS terminates at the SDK; the relay forwards ciphertext | The relay still controls routing and availability |
| Relay passively observes a forwarded session | Certificate signatures do not disclose tenant traffic secrets | IPs, SNI, timing, volume, and connection metadata remain visible |
| Tunnel client tries to reuse signing authority for another connection | The signer requires a current lease and a matching, unexpired, single-use ClientHello binding | This is policy enforced by the relay, not protection from a malicious relay operator |
| Relay splits a recognized probe into two TLS sessions | Different exporter values produce a suspected-termination verdict | Only that sampled connection is checked |
| Fully malicious relay controls the certificate key | It can authenticate as a tenant endpoint; Portal does not cryptographically prevent impersonation | It may selectively forward, distinguish, or drop probes |
| Future Delegated Credentials support | Could avoid contacting the signer on each compatible handshake | Not implemented; retaining the parent certificate key still retains its authentication authority |

The relay's certificate signing authority is distinct from the tenant TLS
session secrets. Reducing online signing or distributing the signer does not
by itself transfer hostname authentication to the tunnel. The article's
[future directions](/keyless-tls#what-would-change-the-trust-boundary) distinguish
those changes.

## MITM Self-Probe

After real application traffic starts, the native SDK asynchronously opens a
separate TLS connection to its public tenant hostname. A random nonce identifies
the returning probe after SDK-side TLS termination. Both TLS endpoints export
keying material with the same label and context, and the SDK compares the values.

- Matching values support passthrough for that sampled connection.
- An exporter mismatch is logged as suspected relay-side TLS termination.
- `--ban-mitm` (or `BAN_MITM`) closes and blocks the detected relay within the
  current exposure. This is not a persistent or network-wide ban.
- Timeouts, connection failures, and other probe errors are warnings, not
  exporter-mismatch verdicts; they do not trigger that block.

Serving traffic does not wait for the probe to pass. The probe is triggered by
traffic, limited to one in flight, and rate-limited after a completed result.
It cannot establish that other clients or connections were forwarded honestly.
In particular, selective MITM and probe distinguishability remain limitations;
random padding does not establish that probes are indistinguishable from normal
application traffic.

Both sides must support TLS keying material export. An explicit `--ban-mitm`
request fails at startup when the selected tenant TLS stack lacks that
capability. Browser/WASM exposures cannot use the native socket-based
self-probe or request this option. Static cache mode explicitly allows relay TLS termination,
disables probing, and cannot be combined with `--ban-mitm`.

The [probe implementation](https://github.com/gosuda/portal-tunnel/blob/main/sdk/mitm.go)
defines these verdicts and their lifecycle. A successful probe is evidence about
one connection, not an authorization to trust every future connection.

## Relay Visibility

For a relay following the ordinary uncached forwarding path, visibility is as
follows. The malicious certificate-owner case above is outside this passive
confidentiality guarantee.

| Relays can see | Protected on that forwarding path |
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

- [Keyless TLS Explained](/keyless-tls) - handshake, signer policy, and self-probe rationale
- [Architecture](/architecture) - deep dive into Portal's internal design
- [Wallet and ENS](/wallet-and-ens) - admin tokens, wallet auth, and ENS gasless DNS import
- [Self-Hosting](/self-hosting) - run your own relay server
