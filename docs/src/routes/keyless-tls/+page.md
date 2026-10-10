---
title: Building End-to-End TLS Tunnels Without Delegated Credentials
description: How Portal combines Keyless TLS, connection-bound signing, and TLS exporter self-probes, and where relay trust remains.
---

<script>
import Mermaid from '$lib/components/Mermaid.svelte'

const handshake = `sequenceDiagram
    participant Browser
    participant Relay
    participant Tunnel
    participant App as Local app
    Browser->>Relay: ClientHello for tenant hostname
    Relay->>Tunnel: Routed stream and connection binding
    Tunnel->>Relay: /v1/sign: lease token, binding, transcript
    Relay-->>Tunnel: CertificateVerify signature
    Note over Browser,Tunnel: Tenant TLS 1.3 handshake completes through the relay
    Browser->>Relay: Tenant TLS records
    Relay->>Tunnel: Forward ciphertext
    Tunnel->>App: Decrypted application request`

const probes = `flowchart TB
    subgraph Pass["Forwarded probe: matching exporters"]
        direction LR
        P1["Probe client"] -->|"TLS ciphertext"| R1["Relay"]
        R1 -->|"Same TLS session"| T1["Tunnel TLS endpoint"]
    end
    subgraph Split["Split probe: different exporters"]
        direction LR
        P2["Probe client"] -->|"TLS session A"| R2["Relay terminates TLS"]
        R2 -->|"TLS session B"| T2["Tunnel TLS endpoint"]
    end`
</script>

# Building End-to-End TLS Tunnels Without Delegated Credentials

Portal combines Keyless TLS, connection-bound transcript signing, and TLS
exporter self-probes to reduce relay trust. The relay still owns certificate
signing authority. Understanding both facts is necessary to decide whether its
default HTTPS path fits an application.

This article explains that design. The [Security Model](/security-model) is the
canonical reference for current guarantees and mode-specific exceptions.
External browser and standards context was reviewed on 10 October 2026.

## Where an ordinary edge tunnel sees plaintext

A reverse proxy can accept browser TLS at a public edge, inspect the HTTP
request, and open a second encrypted connection to a local application. Both
network legs are encrypted, but the edge processes plaintext between them.

Portal's ordinary uncached HTTPS stream takes a different path. The relay reads
the ClientHello to select a tenant, then forwards encrypted records over a
reverse connection already opened by the tunnel. The SDK on the user's machine
terminates tenant TLS and delivers the request to the local application.

<Mermaid code={handshake} />

The public browser uses ordinary certificate validation. It does not need a
Portal-specific verifier or access to the tunnel's wallet identity. That makes
certificate ownership the difficult part: a browser must accept the tunnel's
TLS handshake for a hostname under the relay's domain.

## Keep the certificate key out of every tunnel

Copying a relay's wildcard certificate private key into each tunnel would give
every recipient signing authority over other names covered by that certificate.
Compromise of one tunnel could then expose the shared credential.

Portal keeps that key at the relay. The SDK receives the certificate chain and
asks the relay for a signature while completing the tenant handshake locally.
Its ephemeral key exchange and traffic secrets stay at the TLS endpoints.
Certificate authentication and session encryption therefore have different
owners in this design.

The current tenant terminator is TLS 1.3. Relay API HTTPS and the reverse
carrier are separate TLS layers; their termination at the relay does not give
it the inner tenant traffic secrets. Browser/WASM exposures preserve that inner
boundary over a WebSocket carrier, but do not have the native socket-based
self-probe.

Possession of the certificate key does not decrypt a passively forwarded
TLS 1.3 session, but it does let a
malicious relay authenticate a new TLS session of its own. The relay still
controls the public ingress point where it could do that.

## Constrain the online signer to a routed connection

A remote signing API needs more than a valid tenant login. An unrestricted
interface accepting arbitrary bytes would give its callers authority far beyond
the connection they are serving.

Portal's `/v1/sign` accepts a structured TLS transcript request. The relay
requires a token for a current public lease. When routing a tenant connection,
it creates a random binding associated with that lease, an expiry, and the
ClientHello it observed. The SDK must return that binding with its signing
request.

Before signing, Portal checks that the binding exists, is unexpired, belongs to
the authenticated lease, and matches the captured ClientHello hash. It consumes
the binding so that it cannot be reused. The signer then builds the TLS 1.3
`CertificateVerify` input from the supplied handshake fields.

Portal compares the ClientHello with its ingress observation; it does not independently observe and validate every
server-side transcript field. The signing operation is restricted to the TLS
context and an authorized routed connection, rather than being an
arbitrary-digest service.

The [binding registry](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/bindings.go)
and [signer](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/signer.go)
enforce this policy. They protect an honest relay from misuse by tunnel clients.
They cannot constrain a relay operator who controls the private key and can
replace the policy code.

## Compare the two ends of a sampled TLS connection

The native SDK adds an active check. After application traffic starts, it opens
a separate TLS connection to its own public tenant hostname. The initiating
side verifies the hostname against the relay certificate chain that the SDK
has obtained. Public relay connections use normal CA verification; the
[local-development bootstrap](/security-model#local-development-trust) has a
separate trust policy. A random nonce sent inside the connection lets the tunnel
recognize the returning probe before forwarding it to the application.

Both ends use the same TLS exporter label and context to derive a value from
their TLS session. If the relay forwards the probe, the two ends belong to the
same session and their exporter values match. If it terminates TLS and starts
a second session toward the tunnel, the two sessions produce different values.
TLS exporters are specified in
[RFC 8446, section 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).

<Mermaid code={probes} />

The SDK's [probe code](https://github.com/gosuda/portal-tunnel/blob/main/sdk/mitm.go)
compares the values locally. By default a mismatch produces a warning. With
`--ban-mitm`, it closes that relay listener and blocks the relay within the
current exposure. Timeouts and connection or handshake failures are warnings,
not mismatch verdicts, and do not trigger the block.

Traffic is already flowing when this asynchronous check runs. A matching
result therefore establishes passthrough only for the sampled connection; it
does not certify the relay, prove prior requests were safe, or guarantee what
will happen to another client's connection. A malicious relay might forward
recognizable probes while attacking other traffic, or prevent a probe from
finishing. Random padding does not prove that probes are indistinguishable
from real application traffic.

An explicit blocking request fails at startup if the tenant TLS stack cannot
export keying material. This capability check is useful, but it does not turn
the asynchronous probe into a gate that withholds all traffic until verification.

## Why not use Delegated Credentials?

[RFC 9345](https://www.rfc-editor.org/rfc/rfc9345.html#section-3.2) lets a
certificate holder authorize a separate, short-lived key for TLS
authentication. A tunnel using that key could perform compatible handshakes
without an online call to `/v1/sign`. Deployment requires supporting peers and
a certificate authorized for delegation.

DCs do not revoke the certificate holder's authority. If the relay retains the
parent private key, it can issue another credential or authenticate with the
original certificate. That follows from the RFC's signing and validation rules;
it is not a way to make an untrusted certificate owner unable to impersonate a
tenant. Portal does not currently implement DC negotiation or issuance.

Browser deployment is part of the motivation for the existing design. The
project discussion in [Portal #537](https://github.com/gosuda/portal-tunnel/issues/537)
reports [Chromium #557778448](https://issues.chromium.org/issues/557778448) as
P4 / not planned and attributes the decision to post-quantum costs. The Chromium
tracker was not independently accessible during this article's source review;
that status is a project report, not a verified current browser-support claim.

The byte-cost concern has a concrete basis. Cloudflare's
[October 2025 MTC explanation](https://blog.cloudflare.com/bootstrap-mtc/)
lists a 1,312-byte public key and a 2,420-byte signature for ML-DSA-44. If an
additional key/signature pair uses that algorithm, those pieces alone total
3,732 bytes. This arithmetic excludes framing and is not an exact measurement
of an encoded delegated credential or the net increase over another handshake.

## Merkle Tree Certificates solve a different problem

The Chrome team's
[February 2026 MTC announcement](https://blog.google/security/cultivating-a-robust-and-efficient-quantum-safe-https/)
describes compact inclusion proofs in a CA-signed tree as a way to reduce
post-quantum certificate overhead and integrate issuance transparency.

That changes how certificate authentication is conveyed. It does not, by
itself, move Portal's private keys to the tunnel or delegate an existing relay
certificate's authority. A more efficient certificate format still leaves the
key-ownership decision to the system using it. MTC is relevant to future WebPKI
design, but it is not a substitute for deciding who may authenticate a tenant.

<h2 id="what-would-change-the-trust-boundary">What would change the trust boundary?</h2>

Three directions affect different parts of the system:

- **Delegated credentials** could reduce reliance on an online signer during
  handshakes. A relay retaining the parent certificate key would remain trusted
  for authentication.
- **An independent or threshold signer** could reduce the power of one relay
  compromise if the signer enforces independent authorization. It introduces
  another trust and availability boundary; it is not equivalent to
  browser-verifiable delegation or removal of certificate-owner authority.
- **Tunnel-owned certificates and private keys** could move ordinary hostname
  authentication to the endpoint. The issuer authorization and renewal path
  must also prevent a relay from obtaining a competing certificate for that
  hostname. Moving a key while leaving unrestricted issuance at the relay
  would leave another impersonation path.

These are future directions, not guarantees of today's managed Keyless TLS.
The relay would still control forwarding, availability, and traffic metadata
even if its authentication authority were reduced.

## Choose the mode with its boundary in mind

This article's passive-confidentiality claim concerns ordinary uncached HTTPS.
`--cache` explicitly lets selected relays store site files and terminate browser
TLS, including when they fetch a cache miss from the live tunnel. Raw TCP and
UDP do not add tenant TLS; their applications must supply any required
encryption. Browser/WASM cannot use the native socket-based self-probe.

For native HTTPS, `--ban-mitm` offers a local response to a detected mismatch,
not universal protection from a malicious certificate owner. Choose the relay
operator accordingly, and consult the
[trust table](/security-model#relay-trust-reduction) for the precise guarantees
and exceptions.

## Implementation references

- [Tenant TLS terminator](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/client.go): certificate material, remote signer, and TLS endpoint.
- [Connection bindings](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/bindings.go): lease and captured-ClientHello checks, expiry, and consumption.
- [Signer endpoint](https://github.com/gosuda/portal-tunnel/blob/main/portal/keyless/signer.go): Portal policy around transcript signing.
- [Native self-probe](https://github.com/gosuda/portal-tunnel/blob/main/sdk/mitm.go): exporter comparison, warnings, and blocking behavior.
- [Honest-relay probe E2E](https://github.com/gosuda/portal-tunnel/blob/main/e2e/mitm_test.go): a real traffic-triggered passthrough check, not an exhaustive malicious-relay proof.
