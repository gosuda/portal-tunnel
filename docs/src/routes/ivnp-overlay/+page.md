---
title: IVNP Relay Overlay
description: Optional authenticated relay connectivity over IVNP/I2P.
---

# IVNP Relay Overlay

Portal can embed IVNP to exchange relay catalogs and carry authorized SNI
streams between two public Portal relays. IVNP/I2P owns internal tunnel
construction and intermediate router selection. Portal owns public relay
identity, admission, lease authorization, and public ingress selection.

Ordinary `portal expose` and portal-agent tunnels continue to use a direct
outbound reverse backhaul. They do not construct an intermediate relay path.

## Enable the relay overlay

On Linux or macOS, configure each public relay with:

```dotenv
DISCOVERY=true
IVNP_CONFIG=/portal-certs/ivnp.conf
```

`IVNP_CONFIG` is empty by default. It enables the overlay when set and requires
`DISCOVERY=true`. The public HTTPS origin must still be reachable. The bundled
Compose file passes this variable through; keep the configuration and state
under a persistent mounted directory such as `/portal-certs`.

IVNP creates its configuration when absent. Portal disables the embedded SAM,
HTTP proxy, SOCKS proxy, and control listeners because it uses the destination
directly. Other IVNP routing, bandwidth, and transport settings belong to the
IVNP configuration. The application destination's private key is saved at
`<IVNP_CONFIG>.destination` with mode `0600`; protect and persist that file
together with the router state. Do not share one configuration/state directory
between concurrently running relays.

Startup waits up to two minutes for destination readiness. A configured overlay
that cannot start fails relay startup explicitly. Windows keeps the direct
relay mode and reports an unsupported-platform error if IVNP is requested.

Signed Portal descriptors advertise `ivnp_destination`. Peers compare that
destination with the cryptographically authenticated remote endpoint supplied
by I2P. Descriptor signatures, freshness, catalog bans, and rotation/rollback
checks remain Portal decisions. An I2P identity is not Portal admission or
Sybil resistance.

HTTPS remains discovery bootstrap/recovery and the source of public latency
and health measurements. IVNP refreshes a cached peer at most once per two
minutes, with bounded concurrent requests. Overlay failures and RTT do not
update the public relay score or establish public ingress health.

## Attach an existing lease to a remote backhaul

The initial overlay API supports callers that already manage both leases and
their tenant TLS configuration. It does not add CLI/agent path orchestration.

1. Register an SNI lease on public ingress relay A.
2. Register a lease with the same tenant name and signing identity on relay B.
3. Connect the tunnel endpoint's ordinary reverse stream to B.
4. Configure the tunnel endpoint to terminate TLS for A's public lease hostname,
   using A's keyless signer and A's lease access token. For ECH, use A's lease
   routing metadata and matching endpoint keys. A standard SDK listener
   configured only for B's hostname is insufficient for this attachment.
5. Fetch B's current signed descriptor and send this request to A:

```http
PUT /sdk/relay
X-Portal-Access-Token: <A lease token>
Content-Type: application/json

{
  "relay": { "...": "B's complete signed RelayDescriptor" },
  "access_token": "<B lease token>"
}
```

A authenticates B over IVNP and checks that B's token refers to a local SNI
lease with exactly the same tenant identity. The response uses the regular API
envelope and includes `attached` and `expires_at`.

```text
Browser -- HTTPS/SNI --> A -- IVNP --> B -- direct reverse stream --> endpoint
                                                                   tenant TLS
```

The attachment is stored on A's existing lease. There is no separate route
installation, hop token, intermediate relay list, or worker lifecycle. B must
terminate the incoming overlay stream at its local reverse backhaul. A binding
on B cannot be used to construct A → B → C forwarding chains.

Refresh the binding with a fresh signed descriptor and renewed B token before
the returned expiry. Renewing A's lease does not extend B's authorization.
Expired authorization or an unavailable overlay causes new forwarded streams
to fail; it does not silently select a direct path. Existing accepted streams
may finish. Removing A's lease removes the attachment with it.

To resume A's ordinary local reverse backhaul:

```http
DELETE /sdk/relay
X-Portal-Access-Token: <A lease token>
```

Both lease operators retain tenant admission and byte-rate limits. UDP and
dedicated raw TCP leases cannot use this SNI attachment. The overlay runtime
bounds open streams and handshake/header sizes and closes its active streams
on shutdown. Its private `/relay/lease` and `/relay/connect` endpoints are
reachable only behind IVNP peer authentication, not on public HTTPS.

## NATed intermediate capacity

Volunteer middle capacity belongs to the IVNP router network. Portal does not
publish a worker descriptor, select a volunteer, or assign it a public ingress
hostname or application exit role. Configure router bandwidth and participation
through IVNP. Portal's public relay selection continues to contain public
Portal relays only.

This does not establish that an arbitrary I2P router forwards only Portal
traffic. The original #358 worker-specific restriction is not an I2P network
guarantee. A live NAT/CGNAT topology, transit participation, and operator drain
behavior still require deployment validation against IVNP. Local protocol tests
do not establish those properties or anonymity guarantees.

## Migration

Remove `WIREGUARD_PORT`, `--wireguard-port`, `--multi-hop`, `--multi-hop-depth`,
their environment/TOML equivalents, and old `/sdk/hop` calls. WireGuard keys are
no longer generated or persisted in the Portal relay identity. Tunnel and
discovery protocol version 9 require upgrading clients and relays together.

Public HTTPS/SNI ingress, keyless tenant signing, regular lease operations,
public relay selection, and direct TCP/QUIC backhauls remain available without
IVNP. There is no parallel WireGuard mesh or automatic intermediate path
selection in Portal.
