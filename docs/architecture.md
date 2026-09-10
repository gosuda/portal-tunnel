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

See [ADR index](adr/README.md) for the relay overlay migration decision and
[the site architecture documentation](src/routes/architecture/+page.md) for the
rest of the system.
