# Maintainer Architecture and Package Ownership

> [!NOTE]
> This document details internal Go package ownership, data flows, and subsystem boundaries
> for maintainers and contributors.
> For the public system architecture, protocol flows, and sequence diagrams, see the
> [Public Architecture Guide](https://gosuda.github.io/portal-tunnel/architecture) on the documentation site.

## Relay Transport Architecture & Subsystems

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS normally terminates at the tunnel client. Explicitly opted-in
static caches terminate browser TLS at the selected relay and serve only the
identity-bound canonical hostname; friendly aliases remain live-origin routes.

### Package Boundaries

- `portal/cache`: owns the static cache feature on both sides of the wire.
  `Manager` handles admission, storage, expiry, lease events, and serving;
  `Source` builds shared immutable manifests and `Syncer` handles relay
  synchronization. The registry supplies immutable lease observations; server
  integration owns authentication and reverse-stream fallback. SDK exposures own
  source lifecycle, and listeners supply current transport and lease credentials.

- `portal/discovery`: provides blind collaborator relay selection for `sdk.Exposure`.
  Relay selection returns public relay priorities; Portal does not construct an
  ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
  admission, expiry, health, and load remain Portal responsibilities.

- `portal/overlay`: bridges reverse streams over an independent IVNP overlay network.
  Portal selects and authorizes the ingress and gateway and owns identity, leases,
  and delegated reverse capabilities. IVNP owns the gateway-to-ingress path,
  including routers, tunnels, and internal hop ordering. Direct reverse transport
  remains the tunnel default and fallback. See the
  [Public Architecture Guide](https://gosuda.github.io/portal-tunnel/architecture#ivnp-backed-overlay-networking)
  for the protocol flow.

- `sdk.Exposure`: the public SDK facade centered on a multi-relay `net.Listener`.
  `sdk.Expose` takes its required identity and concrete relay URLs directly; functional
  options cover endpoint capabilities such as UDP, TCP, MITM protection, overlay
  routing, and initial lease metadata. The `sdk.WithDiscovery` option enables
  discovery-driven relay membership: when set, `Exposure` delegates relay selection
  to `portal/discovery` as a blind collaborator, feeding it failure classifications
  from listener events and applying the collaborator's membership decisions through an
  internal membership callback. `AddRelay` and `RemoveRelay` route user intent
  through the collaborator: a removed relay is deactivated out of active selection
  (kept as a future candidate), and a re-added relay is made immediately eligible again.
  `Exposure` owns the logical multi-relay lifecycle and listener membership; it does
  not implement discovery or relay-selection policy. Applications provide only user
  intent — explicit relays, discovery on/off, max active relays, and transport
  requirements — and never interact with the discovery controller, watch callbacks,
  or failure feedback directly. Readiness and accept operations do not infer source
  exhaustion from the current membership; they wait for a future membership update,
  context cancellation, or exposure closure. Local TCP/UDP targets belong to
  `sdk.ProxyConfig`, identity file loading belongs to CLI or agent callers, routed HTTP
  route tables belong to `sdk.NewHTTPRoutes`, and x402 payment gating belongs to the CLI
  and agent composition over `portal/x402`. `Exposure` owns one canonical relay-status
  map; listener events update it, while `Relays`, `Updates`, and `WaitReady` read
  from that state. Agent status types are not part of the SDK contract.

- `portal/keyless`: the tenant TLS feature boundary. It owns tenant TLS termination
  via the `keyless_tls` t13server and keyless remote signing — certificate chains
  are pinned from the relay, each handshake signs transcript-bound through the
  relay's `/v1/sign` endpoint, and the relay validates every signing request against
  a live per-connection binding while keeping lease lifecycle and DNS publication
  orchestration to itself.

## Identity Challenges

`portal/identity` owns the EIP-4361 message model, formatting, and verification
shared by tunnel registration and agent browser wallet login, while the agent
owns the wallet-login lifecycle. Portal emits version 1, chain ID 1 messages
with LF separators. Nonces use `crypto/rand`; the existing secp256k1 and Keccak
primitives own EIP-191 personal-sign hashing and signer recovery. Personal-sign
signatures use `r || s || v`, with `v` in `0/1` or `27/28`.

The server retains the exact challenge message, expected address, and expiry.
Verification requires an exact message match, an unexpired challenge, and a
signature recovering the expected address. It does not parse server-generated
messages back into a second set of domain/nonce fields. The signed RFC3339
expiration remains authoritative at second precision, including the existing
inclusive cutoff. Registration challenge consumption and wallet allowlists,
sessions, and challenge consumption remain with their respective owners.

This supports Portal-issued EOA challenges. Arbitrary SIWE messages and
contract-wallet verification are outside this contract.

## Admission and Identity Policy

The relay hands root/API and cache TLS connections from its SNI ingress directly
to the API server, preserving the original socket peer without a local TCP hop.
Forwarded HTTP headers are accepted only from explicitly trusted proxies; the
relay resolves the client source once at its ingress and passes the result to
protocol handlers and diagnostics as a value.

Durable approval, denial, banning, and routing are keyed by verified Portal
identity and owned by the relay. An admin access change edits a detached snapshot,
persists the complete candidate, then commits it with a monotonically increasing
revision. The relay publishes identity, routability, and revision values to
Portal before acknowledging the update. Portal rejects revisions older than the
newest complete snapshot it has observed, including after idle identity cleanup.
Projection targets include live lease identities and owners of retained offline
cache snapshots, so mode changes also revoke cache-only identities. Registration
reloads the committed snapshot if its publication is rejected.
Revisions are local to a running relay; both sides start fresh on restart.

Revocation detaches cached content and advances the retained lease's cache
generation. Cache requests capture that generation before the final access
check, and must still match it at publication. This fences uploads that overlap
a ban while allowing fresh uploads after an unban without re-registering.

Source IP remains diagnostic metadata and an ephemeral pre-auth admission signal.
Registration challenges, registration attempts, and discovery announces share weighted
per-source and global budgets owned by the relay's admission limiter. The relay applies
these before decoding and signature work, returns 429 with retry guidance, and records
bounded rejection metrics. Authenticated lease operations do not spend the source
budget.
