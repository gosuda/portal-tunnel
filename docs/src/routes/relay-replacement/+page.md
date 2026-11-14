---
title: Relay Replacement
description: Replace a relay using an external TCP entry point and operator-managed tunnel membership.
---

# Relay Replacement with External Infrastructure

Use your TCP entry point and deployment tooling to prepare a second relay,
switch new customer connections, and retire the first process. Keep Portal
running on both sides until existing customer connections have finished or
the external drain deadline expires. Calling Portal shutdown at cutover
closes its ingress and lease resources; it does not start a graceful drain.

This is an operator-managed deployment procedure using existing APIs. Portal
does not notify tunnels of replacement, coordinate policy between processes,
or provide an atomic readiness gate or rollback command. Rehearse the entire
procedure in your environment before using it for production traffic.

## Scope and prerequisites

The concrete example below is deliberately limited to named HTTPS services
using legacy Keyless hostnames, explicit SDK relay membership, external DNS,
and operator-managed relay certificates. Keep discovery, overlay, raw TCP,
UDP, static relay caching, ENS automation, and automatic tenant issuance off.
Do not use `WithAutomaticTLS` or `WithTLSCertificate` in this example.

Local TLS leases publish exact service/address DNS records. Their cleanup
checks ownership within one relay, not across two processes. Merely sharing a
DNS zone or state directory does not make overlapping Local TLS replacement
safe. That configuration needs separate coordination and is outside this
procedure. Keyless continues to rely on the relay's signing authority; this
example does not change that trust model.

Both relay versions must accept the tunnel client's protocol version. An
incompatible new relay cannot be prepared with that client, so keep the old
deployment serving. See [Upgrading](/deployment#upgrading).

## Fixed customer address, explicit control endpoints

This example runs nginx and two separate `relay-server` processes on one Linux host. DNS for
`portal.example.com` and `*.portal.example.com` points at that host throughout.
Only the customer entry point changes its upstream:

```text
Customer: https://app-<address>.portal.example.com:443
  -> dedicated nginx TCP listener :443
       -> old relay :8443 (existing connections)
       -> new relay :9443 (connections accepted after cutover)

Tunnel SDK -> https://portal.example.com:8443 -> old lease and credentials
           -> https://portal.example.com:9443 -> new lease and credentials
```

| Setting | Old relay | New relay |
| --- | --- | --- |
| `PORTAL_URL` | `https://portal.example.com:8443` | `https://portal.example.com:9443` |
| `SNI_PORT` | `8443` | `9443` |
| `IDENTITY_PATH` | `/srv/portal/blue` | `/srv/portal/green` |
| `APPROVAL_MODE` | `manual` | `manual` |
| `DISCOVERY`, `UDP_ENABLED`, `TCP_ENABLED` | `false` | `false` |
| `CACHE_ENABLED` | `false` | `false` |
| `TENANT_CERTIFICATES`, `ENS_GASLESS_ENABLED` | `false` | `false` |

Use `ACME_DNS_PROVIDER=cloudflare` to select an external provider for this
example, and protect each admin endpoint with its own `ADMIN_TOKEN`.
Before startup, provision valid `fullchain.pem` and `privatekey.pem` copies
covering the root and wildcard in each **separate** identity directory. Use
fresh directories without ACME account/registration or tracked ENS state so
the PEM files are recognized as manual overrides. An external certificate
manager owns renewal and deployment of those copies. See
[manual certificate configuration](/configuration#tls).

Do not share `policy.json`, identity files, or writable certificate directories
between the processes. Disable the built-in HTTP redirect listener and keep
the fixed-port control endpoints available to the SDK throughout draining.
Firewall these endpoints to the intended tunnel and operator networks; they
also accept tenant SNI and must not become an uncontrolled customer entry.
The public :443 proxy must additionally allow only explicitly listed customer
SNI names. Portal routes root-host and SNI-less TLS to its API handler, so
forwarding all :443 traffic would expose that API through the proxy despite
the control-port firewall. Keep the root hostname out of the public allowlist.

The SDK currently derives the port in `PublicURL` and `AliasURL` from the
relay URL. It will report `:8443` or `:9443` here, not the customer's `:443`.
Publish the stable customer URL through your own application configuration.
Use the hostname from the selected lease, with the public entry port, and
verify that exact hostname on both relays. Do not change control URLs to
`:443` at cutover: old renewal, signing, and reverse connections must keep
reaching the old process.

## Prepare every tunnel before switching

The application hosting the SDK owns relay membership. It can start an
exposure with both operator-approved control URLs, or add the new one without
restarting the exposure:

```go
if err := exposure.AddRelay("https://portal.example.com:9443"); err != nil {
    return err
}
```

Keep discovery disabled so it does not select or reintroduce another relay.
The existing tunnel identity signs a fresh registration at the new endpoint;
each listener has its own lease and tokens. `AddRelay` is not a readiness
barrier. Check `exposure.Relays()` for **each** target relay and service, wait
for `RelayReady`, and inspect failures and the granted hostname. Aggregate
`WaitReady` can be satisfied by the old relay and is insufficient here.

The application must already permit the stable customer host in its routing,
authentication, and redirect configuration. Require consistent alias ownership
on both relays when using aliases. For this example the identity-bound legacy
hostname avoids a global alias collision, but the service identity and name
must still match on both sides.

Maintain one operator-owned policy source and serialize its application to
both admin endpoints. Explicitly approve the same service identities before
checking readiness. Do not assume the two local policy files synchronize.
Continue updating both relays through the drain period. Apply revocations to
both; if one cannot enforce a denial, fence or stop it, even when that
interrupts its draining connections. Redirecting only new connections does not
revoke an established connection. This procedure supplies no distributed
acknowledgment guarantee.

Record the service set being moved. Freeze additions during preparation, or
have your deployment controller enroll every new/reconnected service on both
relays and include it in verification before cutover. For each hostname,
verify trusted TLS and real application access directly through the new
relay, for example:

```sh
curl --fail --show-error \
  --resolve app-ADDRESS.portal.example.com:9443:SERVER_IP \
  https://app-ADDRESS.portal.example.com:9443/health
```

Replace the hostname and path with the actual service and a safe application
probe. For a private CA, use `--cacert` with the intended trust root, not `-k`.
This direct probe uses the control port; additionally probe the stable URL
and its exact Host through an isolated candidate TCP entry bound to the new
relay. That second check catches public-port redirects, authentication, and
host-routing differences before changing the live entry. A TCP health check
or root `/api/healthz` alone does not verify tunnel serviceability.

## Switch and drain outside Portal

An example [nginx stream configuration](/examples/relay-replacement/nginx.conf)
passes allowed customer TLS through unchanged. Replace the sample hostname
in its SNI map with the exact approved customer names, and update that list
as services are added or removed. Unlisted names, including the root and empty
SNI, go to a loopback rejection listener and never reach Portal. Reserve
`127.0.0.1:10443` for that listener. The map is routing policy, not customer
authentication; application authentication still belongs to the service.

It must be a dedicated instance for this customer entry; tunnel control
endpoints bypass it. It requires nginx 1.21.4 or later with the stream and
[`stream_ssl_preread`](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
modules available. Install the configuration as `/etc/nginx/portal-entry.conf`.
The example uses its own PID file, `/run/nginx-portal-entry.pid`, and separate
logs so signals do not target another nginx master. Provision the prefix and
log directories, validate, and start this dedicated instance before cutover:

```sh
sudo install -d /var/lib/nginx-portal-entry /var/log/nginx
sudo nginx -p /var/lib/nginx-portal-entry/ -c /etc/nginx/portal-entry.conf -t
sudo nginx -p /var/lib/nginx-portal-entry/ -c /etc/nginx/portal-entry.conf
```

Start it only once; a service manager can own the same start command. Use the
same absolute `-p` and `-c` arguments for configuration checks and signals,
and retain the PID path across reloads. Do not use a generic nginx service
reload unless that service is configured to manage this exact instance.
Install its
`worker_shutdown_timeout` **before** the cutover so the workers being retired
already have the deadline configured.

After every target service passes the readiness and application probes,
change the `customer_relay` upstream server from `127.0.0.1:8443` to
`127.0.0.1:9443`, keeping the SNI allowlist and rejection path intact. Validate
the configuration, and reload that nginx instance:

```sh
sudo nginx -p /var/lib/nginx-portal-entry/ -c /etc/nginx/portal-entry.conf -t
sudo nginx -p /var/lib/nginx-portal-entry/ -c /etc/nginx/portal-entry.conf -s reload
```

nginx's [reload behavior](https://nginx.org/en/docs/control.html#reconfiguration)
lets old workers finish accepted connections while new workers use the new
configuration. The
[worker shutdown timeout](https://nginx.org/en/docs/ngx_core_module.html#worker_shutdown_timeout)
bounds the old workers' lifetime. Confirm the reload succeeded and probe the
live stable URL; reload is not an atomic, cross-system readiness transaction.
The stream `proxy_timeout` is an inactivity timeout, not the drain deadline.
Before admitting production traffic, also verify that root SNI, a TLS client
without SNI, and an unlisted hostname are closed on :443 without reaching a
Portal API. The intended tunnel/operator networks must still be able to use
the direct control ports. Repeat these negative probes after cutover.

Leave both Portal processes and SDK listeners alive. Monitor the retiring
nginx workers and their upstream connections; they include accepted customer
TLS handshakes and sockets waiting for a reverse stream. They do not include
the idle SDK reverse carriers, since those use the separate control ports.
When this customer-only worker generation exits, its connections have ended
or have been closed at the deadline. Your deployment controller can then
remove the old listener from each exposure:

```go
if err := exposure.RemoveRelay("https://portal.example.com:8443"); err != nil {
    return err
}
```

Remove the old URL from persistent application configuration too, so restart
does not add it again. Then stop the old Portal process, preserving its private
state for recovery. Do not send Portal SIGTERM at the beginning of drain.
Service-manager termination limits apply to final cleanup after the external
drain, not as a substitute for it.

TLS passthrough cannot count HTTP requests. HTTP/2 connections, keep-alives,
uploads, and WebSockets can continue until the deadline; remaining work may
be interrupted then. Applications own reconnection and state recovery. Do not
automatically replay requests that may already have executed.

## Failures and rollback

Before cutover, leave the live upstream unchanged if any tunnel, policy,
certificate, or probe fails. Remove candidate listeners only after deciding
to abort. After cutover, route new connections back to the old relay only if
its listeners and current policy remain healthy. Keep the candidate process
alive for connections it already accepted.

Reverting an nginx upstream does not move existing sockets or cancel a drain
deadline already running in an older worker generation. Recheck connection
ownership before stopping either process. Once the old process or SDK listener
has stopped, recovery requires restarting/re-registering it; it is no longer
an immediate routing rollback. Keep proxy upgrades and unrelated proxy
reloads out of this replacement window.

## Source addresses and operational verification

The simple TCP proxy opens upstream sockets from its own address. Portal does
not parse PROXY protocol, and `TRUST_PROXY_HEADERS` cannot recover customer IPs
from encrypted tenant TLS. Enforce required customer source restrictions at
the entry point or use separately validated transparent forwarding. Keep
tunnel control source restrictions on the direct endpoints. If your policy
requires the original address at Portal, this simple example is insufficient.

Rehearse delayed responses, uploads, WebSockets, candidate failure, revocation
during drain, deadline closure, and rollback with trusted certificates and your
real network path. Observe both relay logs and the entry point's connection
state. This guide is based on current code contracts and nginx documentation;
the combined deployment has not been established as a production E2E guarantee.
