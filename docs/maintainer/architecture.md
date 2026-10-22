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
  [Relay behavior evidence](relay-behavior.md) records current signal provenance,
  local response boundaries, owner regressions and unobserved attack classes.

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

Reputation uses signed voter cookies. Without a valid cookie, the relay derives
a stable voter from the exact trusted ingress source address (IPv4-mapped
addresses are unmapped). Cookie-free clients behind one NAT share a voter;
existing valid cookies remain separate credentials and keep their identity
when the source changes. IPv6 addresses are not aggregated by prefix. New
cookie-free voters in a service's ledger spend ten additional source/global
admission tokens; existing voters spend only the HTTP request budget. Invalid
sources cannot create voters. This counts voter credentials, not authenticated
people, and preserves existing signed cookies and the persisted ledger format.

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

Cache uploads admit at most two active requests, with one per service identity
(name and address), under the cache manager's lock. Excess requests receive 503;
manifest checks have independent capacity. Revoked PUTs retain admission until
their handlers exit, so restored access may need to retry after a 503.
Upload reads have a ten-second
inactivity deadline and a two-minute absolute limit. A changed manifest retires
the published snapshot so rejected replacement uploads fall back to the origin.

Source IP remains diagnostic metadata and an ephemeral pre-auth admission signal.
Registration challenges, registration attempts, and discovery announces share weighted
per-source and global budgets owned by the relay's admission limiter. The relay applies
these before decoding and signature work, returns 429 with retry guidance, and records
bounded rejection metrics. Authenticated lease operations do not spend the source
budget.

### UDP resource ownership

`RelayDatagram` owns bounded per-lease sender flows and admission of new senders.
`DatagramSession` owns the current QUIC connection and a local lease token carried
as `DatagramFrame.LeaseDone`. Reconnecting the same lease preserves that token;
lease replacement invalidates it, so buffered frames and delayed replies cannot
cross lease instances. Manual SDK datagram replies must preserve the accepted
frame's `LeaseDone` metadata. It is not part of the wire encoding.

The SDK `udpFlowManager` independently bounds local sockets and readers, keys
flows by lease ownership, and closes sockets before joining its workers on
shutdown. An old reader cannot remove or send through a replacement entry.

### TCP bridge ownership

ClientHello inspection and tenant bridges have separate server-wide budgets:
at most 128 sockets may await inspection, and at most 1024 tenant connections
may be pending or active. Root API and reverse-connect handoff does not consume
the tenant budget, so tenant saturation does not prevent a fresh root connection.
The inspection budget is shared across source addresses and the root API; a
single source can occupy all 128 slots until their two-second deadlines expire.
It bounds memory and workers but does not guarantee source fairness or root
availability during a sustained ClientHello flood.

A lease independently admits at most 128 pending reverse acquisitions and active
bridges; the SDK also limits its local TCP proxy workers to 128. Idle established
connections count toward these limits. Capacity is held until the owning worker
finishes, including cancellation and socket cleanup.

The lease registry owns expiry and routing decisions. Admission and final
activation after a reverse wait both read these under the registry lock, then
attach endpoints under the record lock. Activation takes endpoint ownership
before writing the native or WebSocket start frame. The reverse pool still
transfers acquired connections to its caller and only owns idle offers.

Ordinary renewal preserves existing streams. Unregister, expiry, and server
shutdown cancel pending and active lease bridges and close both endpoints.
Routing denial cancels those bridges too; a start-frame write that replaces the
revocation deadline can take up to the framing helper's five-second limit to
finish. Its canceled context prevents application bytes from being copied.
Allowing an identity again admits fresh activity only; canceled reservations
cannot activate. Cancellation also interrupts bandwidth waits.

Copy loops preserve half-close in both directions: an origin can respond after
request EOF, or finish its response while continuing to read the request.
Native replies have no new duration limit. On the WebSocket carrier, yamux's
send-side close starts its default five-minute stream-close timer: a response
still streaming five minutes after request EOF can be reset. This is a carrier
limitation, not an unlimited TCP half-close guarantee. Relay-side revocation may
reach the SDK as a clean EOF; the SDK preserves response-after-EOF semantics and
can retain its local origin socket until the origin closes. Explicit SDK
cancellation or exposure closure closes and joins those local connections.
