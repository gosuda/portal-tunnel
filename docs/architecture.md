# Relay transport architecture

Public clients reach a Portal relay through its existing HTTPS/SNI ingress.
Tunnel clients establish an outbound reverse backhaul to their selected public
relay. Tenant TLS terminates at the tunnel client, not at the relay.

Relay selection returns public relay priorities. Portal does not construct an
ordered list of intermediate relays. Explicit relay URLs, transport eligibility,
admission, expiry, health, and load remain Portal responsibilities.

The optional embedded IVNP router uses one-hop I2P tunnels. Portal applies this
length to the loaded router config; IVNP owns tunnel construction and routing.
Local config and listener errors still fail server startup, but I2P publication
and tunnel warmup do not delay the public HTTPS service. The signed discovery
descriptor advertises the destination only after IVNP reports live inbound and
outbound tunnels and confirmed LeaseSet publication. Server cancellation stops
warmup and closes the router; failed startup also releases the QUIC listener.

The SDK distinguishes gateway HTTPS failures from IVNP reverse-route failures.
An error returned over a working gateway HTTPS connection, or on an established
reverse stream, does not establish a public health failure for either relay.
Such failures retain the normal listener retry budget without removing either
relay from the shared selection pool.

See [ADR index](adr/README.md) for the relay overlay migration decision and
[the site architecture documentation](src/routes/architecture/+page.md) for the
rest of the system.
