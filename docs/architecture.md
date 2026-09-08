# Relay transport architecture

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS terminates at the tunnel client, not at the relay.

Relay selection returns public relay priorities. Portal does not construct an
ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
admission, expiry, health, and load remain Portal responsibilities.

The current runtime has no relay-to-relay data plane. The former Portal-owned
multi-hop route model and WireGuard relay mesh have been removed. An optional
relay overlay must not be added back until it can live behind the ownership
boundary defined by ADR 0001 without changing the generic SDK listener,
discovery route, or lease lifecycle.

See [ADR index](adr/README.md) for the relay overlay migration decision and
[the site architecture documentation](src/routes/architecture/+page.md) for the
rest of the system.
