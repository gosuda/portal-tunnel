# Relay transport architecture

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS normally terminates at the tunnel client. Explicitly opted-in
static caches terminate browser TLS at the selected relay; see
[static cache ownership and limits](adr/0001-static-relay-cache.md).

`portal/cache` owns the static cache feature on both sides of the wire:
`Manager` handles admission, storage, expiry, lease events, and serving;
`Source` builds shared immutable manifests and `Syncer` handles relay
synchronization. The registry supplies immutable lease observations; server
integration owns authentication and reverse-stream fallback. SDK exposures own
source lifecycle, and listeners supply current transport and lease credentials.

Relay selection returns public relay priorities. Portal does not construct an
ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
admission, expiry, health, and load remain Portal responsibilities.

Direct reverse transport is the tunnel default. When a tunnel
enables overlay and the relay has an available IVNP gateway, one relay overlay
runtime carries its reverse TCP streams; direct transport remains the fallback.
The SDK consumes the same generic reverse endpoint in both cases. Discovery
routes and the lease lifecycle contain no overlay topology.

The public SDK facade is centered on `sdk.Exposure`, a multi-relay
`net.Listener`. `sdk.Expose` takes its required identity and concrete relay URLs
directly; functional options cover endpoint capabilities such as UDP, TCP,
ECH, MITM protection, overlay routing, and initial lease metadata. The
`sdk.WithDiscovery` option enables discovery-driven relay membership: when it
is set, `Exposure` delegates relay selection to `portal/discovery` as a blind
collaborator, feeding it failure classifications from listener events and
applying the collaborator's membership decisions through an internal
membership callback. `AddRelay` and `RemoveRelay` route the same user intent
through the collaborator: a removed relay is deactivated out of active
selection (kept as a future candidate), and a re-added relay is made
immediately eligible again.
`Exposure` owns the logical multi-relay lifecycle and listener membership; it
does not implement discovery or relay-selection policy. Applications provide
only user intent — explicit relays, discovery on/off, max active relays, and
transport requirements — and never interact with the discovery controller,
watch callbacks, or failure feedback directly. Readiness and accept operations
do not infer source exhaustion from the current membership; they wait for a
future membership update, context cancellation, or exposure closure. Local
TCP/UDP targets belong to `sdk.ProxyConfig`, identity file loading belongs to
CLI or agent callers, routed HTTP route tables belong to `sdk.NewHTTPRoutes`,
and x402 payment gating belongs to the CLI and agent composition over
`portal/x402`. `Exposure` owns one canonical relay-status map; listener
events update it, while `Relays`, `Updates`, and `WaitReady` read from that
state. Agent status types are not part of the SDK contract.

`portal/keyless` is the tenant TLS feature boundary: it owns keyless remote
signing, TLS config construction, and the ECH layer of that path — tenant
route hostname derivation, fallback hostname hashing, key/ECHConfigList
preparation, lease registration validation, and the HTTPS-record value
encoding. The SDK prepares `keyless.ECHMaterials` once per lease session and
the lease client only transports the prepared fields; the relay validates
them through the same package while keeping lease lifecycle and DNS
publication orchestration to itself.

## Identity challenges

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

See [the site architecture documentation](src/routes/architecture/+page.md) for
the rest of the system.

## Admission and identity policy

The relay hands root/API and cache TLS connections from its SNI ingress directly
to the API server, preserving the original socket peer without a local TCP hop.
Forwarded HTTP headers are accepted only from explicitly trusted proxies.

Durable approval, denial, banning, and routing are keyed by verified Portal
identity. Source IP remains diagnostic metadata and an ephemeral pre-auth
admission signal. Registration challenges, registration attempts, and discovery
announces share weighted per-source and global budgets owned by
`portal/policy.SourceLimiter`. The server applies these before decoding and
signature work, returns 429 with retry guidance, and records bounded rejection
metrics. Authenticated lease operations do not spend the source budget.
