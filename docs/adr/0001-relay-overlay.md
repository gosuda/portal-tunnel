# Relay overlay ownership

Status: accepted for the #324 migration.

Portal owns public relay selection and tenant authorization. The overlay owns
internal routing and intermediate router selection. Maintaining Portal hop
routes alongside an I2P overlay would duplicate those responsibilities.

The migration is split into commits in one PR:

1. Remove Portal multi-hop routes, SDK orchestration, hop tokens, and CLI/agent
   route controls. Public relay selection and direct reverse backhaul remain.
2. Remove the legacy relay peer transport, synchronization, metadata, and
   configuration. HTTPS discovery remains the standalone baseline.
3. Add an optional IVNP relay overlay with authenticated Portal exchanges.

`--multi-hop`, `--multi-hop-depth`, the corresponding environment/TOML keys,
agent multi-hop control, and `/sdk/hop` are removed. Operators must remove these
settings and select public relays through the existing relay selection options.
No compatibility implementation of Portal hop routing is retained.

Overlay reachability does not establish Portal admission or public ingress
health. Overlay latency must not become the public relay performance score.
NATed intermediate capacity belongs to IVNP, not a Portal worker catalog.
