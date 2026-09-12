# Relay transport architecture

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS terminates at the tunnel client, not at the relay.

Relay selection returns public relay priorities. Portal does not construct an
ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
admission, expiry, health, and load remain Portal responsibilities.

The former Portal-owned multi-hop route model and WireGuard relay mesh have
been removed. Direct reverse transport is the tunnel default. When a tunnel
enables overlay and the relay has an available IVNP gateway, one relay overlay
runtime carries its reverse TCP streams; direct transport remains the fallback.
The SDK consumes the same generic reverse endpoint in both cases. Discovery
routes and the lease lifecycle contain no overlay topology.

The public SDK facade is centered on `sdk.Exposure`, a multi-relay
`net.Listener`. `ExposeConfig` contains only relay and lease concerns. Local
TCP/UDP targets belong to `sdk.ProxyConfig`, identity file loading belongs to
CLI or agent callers, and routed HTTP payment settings belong to
`sdk.NewHTTPRoutes`. `Exposure` owns one canonical relay-status map; listener
and discovery events update it, while `Relays`, `Updates`, and `WaitReady`
read from that state. Agent status types are not part of the SDK contract.

## Identity challenges

`types` defines the EIP-4361 message fields shared by tunnel registration and
browser/admin wallet login. `portal/identity` owns their formatting and
verification, while the agent owns the wallet-login lifecycle. Portal emits
version 1, chain ID 1 messages with LF separators. Nonces use `crypto/rand`;
the existing secp256k1 and Keccak primitives own EIP-191 personal-sign hashing
and signer recovery. Personal-sign signatures use `r || s || v`, with `v` in
`0/1` or `27/28`.

The server retains the exact challenge message, expected address, and expiry.
Verification requires an exact message match, an unexpired challenge, and a
signature recovering the expected address. It does not parse server-generated
messages back into a second set of domain/nonce fields. The signed RFC3339
expiration remains authoritative at second precision, including the existing
inclusive cutoff. Registration challenge consumption and wallet allowlists,
sessions, and challenge consumption remain with their respective owners.

This supports Portal-issued EOA challenges, not arbitrary SIWE messages or
contract-wallet verification. `siwe-go` is no longer required; `go-ethereum`
remains an indirect dependency of the separate x402 payment integration.

See [the site architecture documentation](src/routes/architecture/+page.md) for
the rest of the system.
