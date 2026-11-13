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

- `sdk/staticsite`: owns local static file serving, root-confined file access,
  and SPA fallback. SDK routes and embedders use its HTTP handler. Shared path
  resolution remains in `utils`; `portal/cache` owns immutable snapshots,
  cached-content serving, and origin fallback.

- `sdk/appauth`: owns the application sign-in gate, its providers, and its
  sessions. It is public API for programs that embed the SDK, and the CLI uses
  the same package. It stays apart from `sdk` so that `sdk` and its WASM build do
  not depend on OIDC and SAML libraries. `portal/identity` owns the SIWE message
  and wallet challenge code it shares with the agent.

- `cmd/portal-tunnel/tunnel`: owns the tunnel configuration of the CLI and the
  agent. `tunnel.Config` holds what the user set through `portal expose` flags, a
  `[[tunnels]]` entry of the agent config, or an Agent API request.
  `Config.Spec` is the one step from a `Config` to the runtime `Spec`: it
  normalizes the values, fills in the defaults, and validates the result. A
  component with settings of its own keeps its type and its keys with its owner:
  `appauth.Config` with `OIDCConfig`, `SAMLConfig`, and `EmailConfig`,
  `gateway.X402Config`, and `types.LeaseMetadata`. The agent config, the Agent
  API requests, and the agent status embed these components, so a new provider
  setting changes only its component and the validation of that component. The
  agent saves a `Config` as the user set it, plus the tunnel ID and identity path
  that it pins.

  The agent manager owns saved tunnel settings and uses one save-and-apply path
  for additions, updates, and deletions. Metadata and the discovery cap update
  the current exposure; other changed settings restart that tunnel. Runtime
  relay connect/disconnect commands belong to the current SDK exposure and do
  not change the saved settings or the manager's configuration comparison.
  Agent relay status projects the current exposure's state, failure, and
  approval directly. The dashboard uses these observations without tracking
  connection-attempt history. A tunnel without a runtime reports no relay
  endpoints; reading status does not retain a second relay snapshot.

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
  or failure feedback directly. Readiness waits return the current relay errors if
  every selected relay has failed terminally. This is a non-closing snapshot, not
  source exhaustion: the exposure can still accept added or discovered relays.
  Otherwise readiness waits and accept operations continue until a membership or
  readiness update, context cancellation, or exposure closure. Local TCP/UDP targets belong to
  `sdk.ProxyConfig`, identity file loading belongs to CLI or agent callers, routed HTTP
  route tables belong to `sdk.NewHTTPRoutes`, and x402 payment gating belongs to the CLI
  and agent composition over `cmd/portal-tunnel/gateway`. `Exposure` owns one canonical relay-status
  map; listener events update it, while `Relays`, `Updates`, and `WaitReady` read
  from that state. Agent status types are not part of the SDK contract.

- `portal/certmonitor`: independent, warning-only CT and CAA observations. The SDK
  owns the observer lifecycle and passes copied public certificate installation
  events. This package owns polling, baselines, and durable evidence without
  controlling TLS readiness, certificate issuance, or relay selection.

- `portal/keyless`: the Keyless TLS feature boundary. It owns tenant TLS termination
  via the `keyless_tls` t13server and keyless remote signing — certificate chains
  are pinned from the relay, each handshake signs transcript-bound through the
  relay's `/v1/sign` endpoint, and the relay validates every signing request against
  a live per-connection binding while keeping lease lifecycle and DNS publication
  orchestration to itself. A relay certificate renewal needs neither a restart nor
  a reconnect: the relay signs with the key of the certificate the transcript
  presents and keeps a replaced certificate's key until that certificate expires,
  and a tenant checks the chain the relay serves at most once an hour, from its
  lease renewal, and re-pins it when it changed. A handshake that finds the pin
  stale first, because `/v1/sign` reports that the relay holds no key for the
  chain it presents or because the relay's API certificate no longer verifies
  against the pinned chain, is lost and re-pins at once for the handshakes after
  it; the handshakes that fail on the same stale pin share that check. The
  signer connection is always verified against the pinned chain only. An SDK
  that cannot re-pin (it does not send `repins_chain` on renewal) is asked to
  register again, through `lease_not_found` at its next renewal, when the relay
  serves a certificate the chain it registered under does not verify.

Constraints these packages must keep for protocol, security, or platform reasons are recorded in [implementation-invariants.md](implementation-invariants.md).

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
people, and preserves existing signed cookies.

`policy.ReputationStore` owns app votes, comments, comment votes, and voter
identification under one lock. All mutations atomically replace `reputation.json`
before publishing the new in-memory state. App votes and comment threads remain
keyed by stable app identity; comment deletion requires a separate author token.
Comments persist only their ID, text, and creation time; vote counts, viewer votes,
and deletion permission are projected from the ledgers and current requester.
Loading rejects malformed app vote entries and ledgers beyond their capacity
before rewriting the state file.
On loading an older reputation file, the store imports the sibling `comments.json`
and persists the combined state. The old file remains untouched and is ignored
after import, even when all comments have since been deleted. Existing endpoint
paths, response shapes, and per-action admission budgets remain unchanged.
Both vote URLs use one HTTP handler and the store's `Vote` operation. An optional
comment ID selects a comment within the app; the comment route requires it.
Target-specific capacity and admission checks precede the shared vote mutation
and commit. The API builds app summaries or reads the comment list after voting;
the store's vote operation does not construct comment-list responses.

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

Admin changes validate and persist their complete candidate before publishing
access decisions, transport settings, or bandwidth limits. A failed policy-file
write leaves runtime enforcement unchanged and needs no rollback. Portal owns
transport capability validation and applies UDP/TCP policy together under the
registry lock. Bulk bandwidth updates retain existing limiter credit for
identities that remain limited, including those inheriting the relay default;
making an identity unlimited discards its limiter state. `BPSManager` resolves
the startup default only when an identity has no explicit override. Explicit
zero overrides remain in the policy file and mean unlimited. Portal's lease
listing supplies effective bandwidth limits to the admin view; the relay
decorates that listing with its committed access decisions.

`policy.Store` owns one committed snapshot containing approval mode, identity
decisions, UDP/TCP settings, and explicit per-identity bandwidth overrides. Policy
settings and the saved file are projections of this state, rather than
reconstructions from Portal's enforcement state. Both admin update endpoints edit a detached candidate
and share one serialized save-and-apply path. Readers use snapshots without
waiting for file I/O; no separate transport-setting mirror or read lock is needed.

`cmd/internal/cli` owns shared command dispatch, argument parsing, help output,
and environment-backed flags resolved from a captured input for each command.
Plain flags use `flag.FlagSet` directly. The resolved values, variable reference, and parse diagnostics
belong to that resolution. Relay config-file reports use the file as their input
without changing the process environment. Relay API, frontend, domain-report,
and optional x402 routes share one application route table; protocol ingress
and application body limits remain enforced at their respective boundaries.

Relay startup and config diagnostics share one side-effect-free preparation
path, retaining Portal's normalized settings and rejecting invalid environment
values. Portal owns static transport-policy validation; a running server also
checks listener availability before applying changes. Tunnel config-to-spec
conversion uses explicit settings only. The expose CLI resolves environment
defaults during flag registration; the agent applies its facilitator-token
default to a runtime copy without writing that secret into its config file.

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

### Tenant TLS certificate ownership

The negotiated `local-tls-v1` namespace fixes TLS policy by hostname. Friendly
and legacy canonical URLs use the relay-backed Keyless engine. New exact
`<service>.<address>.<root>` canonical URLs use a separate `portal/localtls`
endpoint based on Go `crypto/tls`; they never use Keyless or relay static cache.
Each endpoint retains atomic certificate rotation and in-flight handshake safety.
The SDK dispatches by exact lease hostname and advertises canonical readiness
only while usable local material exists. Legacy clients and relays retain their
original URL and cache behavior through capability negotiation.

The local endpoint's automatic source owns persisted bundles, CSR issuance,
renewal, and cancellation/join of its worker. Only that worker submits CSRs;
lease chain checks reload persisted bundles without starting issuance. The
persisted P-256 key is intentionally reused across retries, renewals, and
restarts; automatic key rotation is not implemented. Failed issuance uses
exponential backoff from one minute to one hour, honoring a relay's `Retry-After`
seconds or HTTP date up to a one-hour cap. Shutdown interrupts requests and
retry waits. Missing or expired local material fails closed on the new canonical
hostname without changing the separate friendly Keyless endpoint.

The SDK lease separately owns the optional CAA/CT observer. It receives the
canonical hostname and bounded, copied public leaf installation events, not the
TLS client, private keys, or lease credentials. The observer owns its own polling,
evidence persistence, and cancellation/join; observations never gate activation.
A dropped event or crash may produce a conservative unrecognized-key warning.
