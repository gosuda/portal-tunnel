---
title: Kubernetes
description: Run the Portal relay and tunnel clients on Kubernetes with Helm charts or plain manifests.
---

# Kubernetes

Portal ships two Helm charts:

- `portal-relay` runs the relay server from the `ghcr.io/gosuda/portal` image.
- `portal-tunnel` runs a tunnel client from the `ghcr.io/gosuda/portal-tunnel`
  image and exposes an in-cluster Service through a relay.

Every tunnel client example also comes as a plain manifest, so Helm is
optional for clients. The examples live in
[`docs/static/examples/kubernetes`](https://github.com/gosuda/portal-tunnel/tree/main/docs/static/examples/kubernetes):

| Example | Shows |
|---|---|
| [`relay-embedded-dns.values.yaml`](/examples/kubernetes/relay-embedded-dns.values.yaml) | Public relay that serves its own DNS zone |
| [`relay-cloudflare.values.yaml`](/examples/kubernetes/relay-cloudflare.values.yaml) | Relay with an external DNS provider |
| [`relay-private.values.yaml`](/examples/kubernetes/relay-private.values.yaml) | Relay that accepts tunnels only from your networks |
| [`tunnel.values.yaml`](/examples/kubernetes/tunnel.values.yaml), [`tunnel.yaml`](/examples/kubernetes/tunnel.yaml) | Client with an identity on a persistent volume |
| [`tunnel-replicas.values.yaml`](/examples/kubernetes/tunnel-replicas.values.yaml), [`tunnel-replicas.yaml`](/examples/kubernetes/tunnel-replicas.yaml) | Two clients serving one URL |
| [`tunnel-sidecar.yaml`](/examples/kubernetes/tunnel-sidecar.yaml) | Client as a sidecar next to the application |

Release tags publish both charts to `oci://ghcr.io/gosuda/charts`, with the
chart version equal to the Portal release. Pin `--version` to the release you
run. From a checkout, install `docs/examples/helm/portal-relay` or
`docs/examples/helm/portal-tunnel` instead.

## Prerequisites

- Kubernetes 1.26 or later, and Helm 3.8 or later for OCI charts.
- Portal v2.8.0 or later. Earlier clients ignore `--name` for an identity
  from a Secret and lack `--replica`. Until v2.8.0 is published, the `2` image
  tag that charts from a checkout use points at an earlier release.
- For the relay:
  - A `LoadBalancer` Service that can publish TCP and UDP on one address. The
    embedded DNS needs `53/tcp` and `53/udp` on the address its NS delegation
    points at. Without a load balancer, set `service.type: NodePort` and route
    the public ports to the node ports yourself.
  - A static public address for that Service, set as `env.PUBLIC_IPS`. See
    the next section.
  - A StorageClass that provides `ReadWriteOnce` volumes.

### The relay's public address

The relay publishes A and AAAA records for its public address, both from the
embedded DNS and through an external DNS provider. Set that address to the
Service address with `env.PUBLIC_IPS`: at most one IPv4 and one IPv6 address,
comma-separated. A family you leave out is not published.

```yaml
env:
  PUBLIC_IPS: 203.0.113.10
```

Without `PUBLIC_IPS`, the relay asks external services which address its
outbound connections come from. On many clusters, outbound traffic leaves
through a node address or a NAT gateway, not through the load balancer, and
DNS then sends visitors and tunnel clients to the wrong address. Discovery also
needs outbound access to those services.

The chart does not copy `service.loadBalancerIP` into `PUBLIC_IPS`. That field
is deprecated, some load balancers ignore it, and behind a DNAT it is not the
public address. A change of `PUBLIC_IPS` takes effect when `helm upgrade`
restarts the pod. See [IPv4 and IPv6](/configuration#ipv4-and-ipv6) for the
full rules, including the cleanup when you drop a family.

## Install the relay

Keep the admin token out of Helm values by creating the Secret first:

```bash
kubectl create secret generic portal-relay \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)"
```

Save the token in your password manager; it signs in to the admin dashboard
and the [Admin and Policy API](/api-reference/admin). Then install the chart
with a values file based on one of the relay examples:

```yaml
# relay.values.yaml
env:
  PORTAL_URL: https://portal.example.com
  PUBLIC_IPS: 203.0.113.10
existingSecret: portal-relay
service:
  loadBalancerIP: 203.0.113.10
```

```bash
helm install relay oci://ghcr.io/gosuda/charts/portal-relay -f relay.values.yaml
kubectl get service relay-portal-relay
```

With the embedded DNS, delegate the relay domain to the Service address once,
as described in [DNS Configuration](/self-hosting#dns-configuration), and publish
the DS record from the startup log for DNSSEC. Follow the first certificate
issuance in the log:

```bash
kubectl logs deployment/relay-portal-relay --follow
```

The HTTPS listener opens once the first certificate is ready. The startup
probe allows ten minutes for that, and the Service sends traffic to the pod
before it is ready, so ACME DNS-01 validation can reach the embedded DNS.

### How values map to the relay

`env` holds relay environment variables: the keys of `.env.example` and the
[configuration reference](/configuration), with the relay defaults for any key
you leave out. `relay-server config --format env` prints every key. Secret
keys, such as `ADMIN_TOKEN`, `ACME_EAB_HMAC` or a DNS provider token, go in a
Secret named by `existingSecret`, or in `secretEnv` for a Secret the chart
creates.

The chart owns four keys and fails if `env` sets them. The relay listens on
unprivileged ports, and the Service publishes them on the standard ones:

| Key | Chart value | Published as |
|---|---|---|
| `SNI_PORT` | `8443` | `443/tcp`, or the port `PORTAL_URL` names |
| `EMBEDDED_DNS_PORT` | `5353` | `53/tcp` and `53/udp` |
| `HTTP_REDIRECT_ADDR` | `:8080` | `80/tcp` |
| `IDENTITY_PATH` | `/portal-certs` | the persistent volume |

The Service publishes only what the relay serves, judged from `env`:

| Setting in `env` | Service ports |
|---|---|
| `ACME_DNS_PROVIDER` empty or `embedded` | `53/tcp`, `53/udp` |
| `HTTP_REDIRECT_ENABLED` | `80/tcp` |
| `UDP_ENABLED` | the HTTPS port over UDP for the QUIC backhaul, and each UDP lease port |
| `TCP_ENABLED` | each TCP lease port |

Lease ports keep their numbers end to end, because the relay announces them to
clients. A Service cannot declare a port range, so the chart lists each port
from `MIN_PORT` to `MAX_PORT`. Keep the range small: many load balancers limit
the ports one Service can publish. Turn UDP and raw TCP on in `env`, not in
the admin dashboard, so that the Service publishes the ports.

The Service uses `externalTrafficPolicy: Local` so the relay sees visitor and
tunnel source addresses, which pre-auth limits and `TUNNEL_SOURCE_CIDRS`
depend on. The relay does not read the PROXY protocol; a load balancer that
rewrites source addresses hides them from the relay.

The persistent volume holds the relay identity, the ACME account and
certificates, the DNSSEC key, `policy.json`, and the static cache. Its default
size leaves room for the 1 GiB default of `CACHE_MAX_BYTES`. `helm uninstall`
keeps the volume claim, so reinstalling with the same release name reuses it.

Files go in through `extraVolumes` and `extraVolumeMounts`, for example a
Google Cloud service-account file:

```yaml
env:
  PORTAL_URL: https://portal.example.com
  ACME_DNS_PROVIDER: gcloud
  GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/gcp/dns.json
existingSecret: portal-relay
extraVolumes:
  - name: gcp
    secret:
      secretName: gcp-dns
extraVolumeMounts:
  - name: gcp
    mountPath: /run/secrets/gcp
    readOnly: true
```

The same pattern mounts a custom frontend for `PORTAL_FRONTEND_DIR`.

## Run a tunnel client

The client needs an identity, which owns its URLs. Choose where it lives:

- **On a persistent volume.** This is the chart default: the client creates
  an identity on first start and keeps it on the volume. It suits a single
  replica.
- **In a Secret.** Several clients and sidecars need this, because clients
  serve one URL together only when they share an identity.

To create an identity for a Secret, generate a private key and a token secret:

```bash
cat > identity.json <<EOF
{"private_key": "$(openssl rand -hex 32)", "token_secret": "$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"}
EOF
kubectl create secret generic my-app-identity --from-file=identity.json
```

The client derives the address and public key from the private key. The
token secret keeps the tokens derived from the identity the same in every
replica and across restarts; without it, each process generates its own. An
`identity.json` that `portal expose` created elsewhere works too, and keeps
that service's URLs.

### With the chart

```bash
helm install my-app-tunnel oci://ghcr.io/gosuda/charts/portal-tunnel -f tunnel.values.yaml
```

| Value | Effect |
|---|---|
| `target` | Address to expose, such as `my-app.default.svc.cluster.local:8080` |
| `name` | Service name for the short URL (`--name`). Optional; an unnamed HTTP service gets `default--<address>.<relay-root>` |
| `relays` | Relay URLs (`--relays`) |
| `args` | Other `portal expose` flags, such as `--discovery=false`, `--tcp` or `--auth` |
| `env`, `secretEnv`, `existingSecret` | Environment variables read by `portal expose`; secret ones, such as `AUTH_OIDC_CLIENT_SECRET`, go in a Secret |
| `identity.existingSecret`, `identity.key` | Secret holding the identity JSON, passed as `IDENTITY_JSON` |
| `replicaCount` | Clients serving the URL; more than one adds `--replica` and needs `identity.existingSecret` |
| `persistence` | Volume for a generated identity; unused with `identity.existingSecret` |
| `metrics` | Prometheus `/metrics` port, liveness probe and optional PodMonitor |

Several clients share one URL in HTTP replica mode (`--replica`), and the
relay spreads new connections among them. Without it, each registration
replaces the leases of the same identity. Replica mode needs a relay that
supports it, and rules out dedicated TCP/UDP ports, the relay cache, overlay,
email and SAML authentication, and paid Nano routes; see
[HTTP Replicas](/api-reference/sdk#http-replicas). The chart adds `--replica`
when `replicaCount` is above 1. If something else scales the Deployment, such
as an autoscaler, add `--replica` to `args`.

With an identity on a volume, the Deployment uses the `Recreate` strategy.
With an identity Secret, a rolling update starts the new client before the old
one stops: in replica mode both serve the URL meanwhile, and a single client
hands its lease over to the new one. A client registers a few seconds after
it starts and has no readiness check for that, so the chart sets
`minReadySeconds: 10` to keep the old client running until then. Set it on
your own Deployments too, as the plain examples do. A single client can still
drop a few requests around the handover; with `replicaCount: 2`, another
client serves the URL throughout a rollout.

### Without Helm

[`tunnel.yaml`](/examples/kubernetes/tunnel.yaml) and
[`tunnel-replicas.yaml`](/examples/kubernetes/tunnel-replicas.yaml) are the
same deployments as the chart examples. Edit the target, name and relay, then
apply them:

```bash
kubectl apply -f tunnel.yaml
```

[`tunnel-sidecar.yaml`](/examples/kubernetes/tunnel-sidecar.yaml) runs the
client in the application's pod, so it reaches the application on
`127.0.0.1` and scales with it in replica mode. It has no chart form, because
a chart cannot add a container to another workload.

### Find the URL

The client logs the URL on the line that starts with `service ready at`:

```bash
kubectl logs deployment/my-app-tunnel-portal-tunnel | grep "service ready at"
```

A relay in `manual` approval mode holds a new client until an admin approves
it; the client logs `waiting for relay approval` meanwhile. A relay with
`TUNNEL_SOURCE_CIDRS` answers `403 source_not_allowed` to other networks. See
[Private relay](/self-hosting#private-relay).

## Operations

**Upgrades.** Relays and tunnel clients must speak the same tunnel protocol
version, so upgrade both charts to the same release together; see
[Upgrading](/deployment#upgrading). Each chart version installs the matching
image tag. The relay runs one pod on a `ReadWriteOnce` volume, so
`helm upgrade` stops it before the new pod starts, and tunnels reconnect once
the new pod listens. For replacement without that gap, see
[Relay Replacement](/relay-replacement).

**Backups.** Back up the relay volume with your volume snapshot tooling.
Losing it means a new relay identity, a new ACME account and new certificates,
and losing `dnssec-csk.json` breaks DNSSEC until the parent zone gets the new
DS record. Back up each client identity Secret, or the client volume; a new
identity is a different owner to the relay, and URLs tied to the old one do
not follow it.

**Admin token rotation.** Update the Secret, then restart the relay:

```bash
kubectl create secret generic portal-relay \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/relay-portal-relay
```

A token in `secretEnv` changes with `helm upgrade`, which restarts the relay
by itself.

**Metrics.** With the Prometheus Operator, `podMonitor.enabled` on the relay
chart scrapes `/api/admin/metrics` with the admin token and the relay host as
TLS server name. `metrics.podMonitor.enabled` on the client chart scrapes the
client's `/metrics`. The
[observability example](https://github.com/gosuda/portal-tunnel/blob/main/docs/examples/observability/README.md)
includes a Grafana dashboard for the relay metrics.

**Leases.** Approve, deny and limit tunnels in the admin dashboard at the
relay URL, or through the [Admin and Policy API](/api-reference/admin).

## Troubleshooting

**The relay pod restarts during its first start.** The HTTPS listener waits
for the first certificate. Check the log for DNS-01 errors, check the NS
delegation with `dig NS portal.example.com`, and check that `53/udp` and
`53/tcp` reach the pod.

**Names resolve to the wrong address.** Set `env.PUBLIC_IPS` to the Service
address; see [The relay's public address](#the-relays-public-address). The
relay logs the addresses it publishes, and whether they come from
`PUBLIC_IPS` or from discovery, on the line `published relay address records`.

**The Service has no address, or lacks the UDP ports.** Some load balancers
cannot mix TCP and UDP on one Service, or need an annotation for it. Check
`kubectl describe service` for events from the cloud provider.

**The relay sees node addresses instead of visitor addresses.** Keep
`externalTrafficPolicy: Local`, and use a load balancer that passes source
addresses through.

**Lease ports are unreachable.** Check that the load balancer accepted every
port of the range, and that UDP and TCP are on in `env`.

**The client runs but never logs `service ready at`.** The liveness probe
checks only `/metrics`, so a client whose relays all refused it stays
`Running`. Look for `failed permanently` in the client log; the error before
it names the cause, such as `hostname conflict`. An
unnamed client with `--tls-auto` on a relay that does not issue tenant
certificates logs the warning `tenant_issuance_disabled` instead.

**The relay or client cannot write its volume.** Both run as UID and GID
65532 and rely on `fsGroup`. With a storage driver that ignores `fsGroup`,
give the volume to 65532 before the first start.
