# Relay transport architecture

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS terminates at the tunnel client, not at the relay.

Relay selection returns public relay priorities. Portal does not construct an
ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
admission, expiry, health, and load remain Portal responsibilities.

The optional `portal/overlay` runtime embeds IVNP on Linux/macOS. It owns the
destination, bounded authenticated exchanges, and stream shutdown. Catalog
admission remains in `portal/discovery`; incoming I2P reachability cannot promote
a public relay's health or affect its measured HTTPS latency.

An existing SNI lease may hold one `relayBinding` to a remote lease with the same
tenant identity. The remote token bounds the attachment's lifetime. Incoming
overlay traffic always claims a local reverse session and cannot follow another
attachment. TLS endpoint configuration remains the API caller's responsibility;
the standard SDK/CLI does not orchestrate bindings. See the
[IVNP overlay guide](src/routes/ivnp-overlay/+page.md) for the complete contract.

See [ADR index](adr/README.md) for the relay overlay migration decision and
[the site architecture documentation](src/routes/architecture/+page.md) for the
rest of the system.
