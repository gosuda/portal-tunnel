---
title: SDK API
description: Portal SDK endpoints for relay discovery, lease lifecycle, and reverse tunnel streaming.
---

# SDK API

SDK endpoints are the stable lease protocol between a Portal tunnel process and
a relay. Normal JSON endpoints use the shared envelope from
[API Reference](/api-reference). `GET /sdk/connect` is the only SDK endpoint
that upgrades from ordinary HTTP into the reverse transport.

## Flow

1. `GET /sdk/domain` checks relay compatibility, optional ENS support, and optional relay-owned Sui x402 control-plane facilitator support.
2. `POST /sdk/register/challenge` creates a SIWE challenge for the requested identity.
3. The SDK signs the returned `siwe_message`.
4. `POST /sdk/register` exchanges the signature for a lease `access_token` and
   a generic `reverse_endpoint`.
5. The SDK keeps the lease alive with `/sdk/renew` and opens reverse streams at
   the returned endpoint using its opaque capability.
6. `POST /sdk/unregister` removes the lease.

## Endpoints

| Method | Path | Auth | Body | Data |
|--------|------|------|------|------|
| `GET` | `/sdk/domain` | None | none | `DomainResponse` |
| `POST` | `/sdk/register/challenge` | None | `RegisterChallengeRequest` | `RegisterChallengeResponse` |
| `POST` | `/sdk/register` | SIWE signature body | `RegisterRequest` | `RegisterResponse` |
| `POST` | `/sdk/renew` | lease token body | `RenewRequest` | `RenewResponse` |
| `POST` | `/sdk/reverse` | lease token body | `ReverseEndpointRequest` | `ReverseEndpoint` |
| `POST` | `/sdk/unregister` | lease token body | `UnregisterRequest` | `{}` |
| `GET` | `/sdk/connect` | reverse capability header or WebSocket subprotocol | none | raw stream or WebSocket/yamux session |
| `POST` | `/sdk/cache` | lease token header | `StaticCacheManifest` JSON | `StaticCacheStatus` |
| `PUT` | `/sdk/cache` | lease token header | manifest and file bytes as multipart | `StaticCacheStatus` |
| `DELETE` | `/sdk/cache` | lease token header | none | `StaticCacheStatus` |

## Domain

`GET /sdk/domain` returns:

| Field | Type | Notes |
|-------|------|-------|
| `protocol_version` | `string` | SDK tunnel protocol version |
| `release_version` | `string` | relay software release |
| `cache` | `StaticCacheLimits` | optional; advertised when static caching is enabled |
| `ens` | `ENSStatus` | gasless ENS status |
| `x402` | `X402FacilitatorInfo` | relay-owned Sui x402 control-plane facilitator status |

`ENSStatus`:

| Field | Type |
|-------|------|
| `enabled`, `verified` | `boolean` |
| `provider`, `address`, `dnssec_state`, `ds_record`, `message`, `last_error` | `string` |

`X402FacilitatorInfo`:

| Field | Type |
|-------|------|
| `enabled` | `boolean` |
| `url`, `network`, `network_name`, `supported_url`, `pay_to` | `string` |

This object describes the relay's own optional x402 facilitator for
control-plane resources. It is separate from tunnel-owned routed HTTP payments,
which are configured locally by the tunnel process.

## Register Challenge

`RegisterChallengeRequest`:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `identity` | `Identity` | yes | `name` and `address` |
| `canonical_hostname` | `boolean` | no | opt in to identity-bound hostname semantics; defaults to `false` for protocol-10 compatibility |
| `metadata` | `LeaseMetadata` | no | public lease metadata |
| `overlay` | `boolean` | no | prefer an [IVNP overlay path](/concepts#ivnp-backed-overlay-networking) when available; defaults to `false` |
| `ttl` | `number` | no | requested TTL in seconds |
| `udp_enabled` | `boolean` | no | request UDP transport |
| `tcp_enabled` | `boolean` | no | request dedicated TCP port |
| `cache` | `boolean` | no | Explicitly permit static storage and relay TLS termination; default `false` |
| `cache_ttl` | `number` | no | Requested offline seconds; `0` uses relay policy, positive values are clamped |

Cache opt-in is incompatible with raw TCP/UDP leases.

`RegisterChallengeResponse`:

| Field | Type |
|-------|------|
| `challenge_id` | `string` |
| `expires_at` | `string` |
| `siwe_message` | `string` |

## Register

`RegisterRequest`:

| Field | Type | Required |
|-------|------|----------|
| `challenge_id` | `string` | yes |
| `siwe_message` | `string` | yes |
| `siwe_signature` | `string` | yes |
| `reported_ip` | `string` | no |

`RegisterResponse`:

| Field | Type | Notes |
|-------|------|-------|
| `identity` | `Identity` | normalized lease identity |
| `hostname` | `string` | friendly hostname; empty for a canonical-capable client when another identity currently holds the friendly name |
| `canonical_hostname` | `string` | relay-derived identity-bound hostname used by the SDK |
| `expires_at` | `string` | lease expiry |
| `access_token` | `string` | token for renew, unregister, signer access, and direct datagram backhaul |
| `reverse_endpoint` | `ReverseEndpoint` | URL, opaque reverse-only capability, and expiry for `/sdk/connect` |
| `udp_addr`, `tcp_addr` | `string` | omitted when transport is disabled |
| `udp_enabled`, `tcp_enabled` | `boolean` | active transport flags |

The SDK uses the returned `canonical_hostname`; it does not derive or accept a
client-supplied address suffix. The canonical label contains the normalized
name, a hyphen, and all 40 lowercase hexadecimal characters of the
SIWE-authenticated Ethereum address. The current SDK advertises canonical
hostname support. A protocol-10 client that omits the capability receives
`hostname_conflict` instead of a canonical-only registration when its friendly
hostname is already owned by another identity.

`ReverseEndpoint`:

| Field | Type | Notes |
|-------|------|-------|
| `url` | `string` | HTTPS `/sdk/connect` endpoint on the ingress relay or its selected gateway |
| `capability` | `string` | opaque, reverse-only, and bound to this lease instance |
| `expires_at` | `string` | never later than the owning lease expiry |
| `overlay` | `boolean` | `true` when the selected endpoint uses the overlay |

The reverse capability is not accepted by renew, unregister, signer, or
datagram endpoints. The lease `access_token` is not accepted by the reverse
endpoint.

The relay preserves the `overlay` preference for the lease lifetime. By
default it issues the ingress relay's direct endpoint. When `overlay` is true,
it prefers an available overlay gateway and falls back to the direct endpoint.
Both modes intentionally preserve the same SDK-facing contract: use the returned
`url` and reverse-only `capability` to open the stream. Portal owns endpoint
selection, identity, lease policy, and authorization; IVNP owns the network path
between gateway and ingress. The SDK does not choose IVNP routers or receive
their topology, and that topology is not part of leases or discovery state.

See [IVNP-backed overlay networking](/concepts#ivnp-backed-overlay-networking)
for the conceptual model and [the architecture](/architecture#ivnp-backed-overlay-networking)
for the delegated capability and gateway-to-ingress protocol flow.

## Renew And Unregister

`RenewRequest`:

| Field | Type | Required |
|-------|------|----------|
| `access_token` | `string` | yes |
| `ttl` | `number` | no |
| `reported_ip` | `string` | no |
| `metadata` | `LeaseMetadata` | no |

`RenewResponse`:

| Field | Type |
|-------|------|
| `expires_at` | `string` |
| `access_token` | `string` |
| `reverse_endpoint` | `ReverseEndpoint` |

`POST /sdk/reverse` rotates only the reverse endpoint. It does not renew or
replace the lease. The request contains `access_token` and may include the
generic `failed_url`; the latter lets the ingress avoid the failed endpoint
when another gateway or the direct path is available.

`UnregisterRequest`:

| Field | Type | Required |
|-------|------|----------|
| `access_token` | `string` | yes |

`/sdk/unregister` returns `{}` on success.

## Static Cache

All `/sdk/cache` operations require
`X-Portal-Access-Token: <lease access_token>` for an active, cache-opted-in lease.
The reverse capability cannot authorize them. Cache capability is optional;
clients retain the live origin tunnel if admission or upload fails.

`StaticCacheLimits` (the optional `/sdk/domain` `cache` object):

| Field | Type | Meaning |
|-------|------|---------|
| `max_exposure_bytes` | number | Total file bytes allowed for one snapshot |
| `max_object_size` | number | Maximum bytes for one file |

`StaticCacheManifest`:

```json
{
  "index": "index.html",
  "files": [
    { "path": "index.html", "size": 5, "sha256": "<64-character SHA-256 hex digest>" }
  ]
}
```

Paths must be safe, relative, unique, and sorted, and `index` must identify a
listed file. Only regular files are eligible. Manifests are limited to 1 MiB
and 2,048 files, in addition to the advertised byte limits.

- `POST`: send the manifest as JSON. `present` indicates whether the matching
  unexpired snapshot exists. A changed manifest invalidates the previous snapshot.
- `PUT`: send `multipart/form-data`, with the JSON manifest as the first part
  (`manifest`), followed by one binary part (`object`) per file, in manifest
  order. Sizes and hashes are validated before atomic publication.
- `DELETE`: invalidate this lease's snapshot; returns `present: false`.

Successful operations return the standard envelope containing
`StaticCacheStatus`: `present` (boolean) and `expires_at` (timestamp when a
snapshot is present). Authentication, expiry, capacity, and method failures
must be handled by HTTP status; not every cache error uses the JSON envelope.
See [cache configuration](/configuration#static-relay-cache) for TTL and storage
limits and [the TLS boundary](/security-model#opt-in-static-cache).

## Reverse Connect

`GET /sdk/connect` opens a native reverse tunnel stream or establishes the
browser reverse multiplexer.

Requirements:

| Requirement | Value |
|-------------|-------|
| HTTP version | HTTP/1.1 |
| Native authentication | `X-Portal-Reverse-Capability: <opaque capability>` header |
| Native connection | keep-alive capable connection that supports hijack |
| Browser authentication | `portal.reverse.v1` and the opaque capability offered as WebSocket subprotocols |
| Browser connection | WebSocket carrying a yamux session; each logical stream presents the current capability again |

For a native connection, the relay writes `HTTP/1.1 101 Switching Protocols`
and hijacks the TCP connection. There is no JSON response body. For a browser
connection, it completes the WebSocket handshake and accepts reverse
connections as yamux streams. Failures before either upgrade use the standard
JSON error envelope.

The SDK keeps several ready reverse streams open. When an end user connects to
the lease hostname, the relay claims one ready stream and bridges encrypted
tenant bytes between the browser side and the SDK side.

<div id="browser-wasm-sdk-runtime"></div>

## Browser/WASM SDK Runtime

The same `sdk.Expose` and `sdk.RunHTTP` lifecycle can run in a Go WebAssembly
application. The application supplies the HTTP handler; the browser runtime is
not a general-purpose bridge to a local port or file.

```go
id, err := identity.Generate("browser-preview")
if err != nil {
    return err
}

exposure, err := sdk.Expose(ctx, id, []string{relayURL})
if err != nil {
    return err
}
defer exposure.Close()

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    _, _ = io.WriteString(w, renderCurrentPreview())
})
return sdk.RunHTTP(ctx, exposure, handler, "")
```

Compile the application with `GOOS=js GOARCH=wasm`. The SDK detects the JS
runtime and uses WebSocket plus yamux for reverse connections; callers do not
select that transport through an option.

A relay exposes the maintained connector and matching Go runtime glue at
`/api/install/bin/js-wasm` and `/api/install/bin/wasm-exec`. Use the
`release_version` returned by `/sdk/domain` as their `version` query parameter
so the relay rejects an incompatible cached artifact.

Browser runtime limits:

- HTTPS handler exposure only
- no raw TCP or UDP exposure
- no overlay transport
- no native MITM self-probe or `WithMITMProtection(true)`
- lifetime bound to the page and application context

The repository's
[`cmd/portal-tunnel/wasm`](https://github.com/gosuda/portal-tunnel/tree/main/cmd/portal-tunnel/wasm)
command is the maintained JS interop reference. See
[Browser reverse transport](/architecture#browser-reverse-transport) for the
carrier protocol and [Browser/WASM transport](/security-model#browser-wasm-transport)
for its trust boundary.
