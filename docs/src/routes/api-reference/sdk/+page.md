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
| `allow_canonical_fallback` | `boolean` | no | allow canonical-only registration when the friendly alias is unavailable; defaults to `false` for protocol-10 compatibility |
| `metadata` | `LeaseMetadata` | no | public lease metadata |
| `overlay` | `boolean` | no | prefer an [IVNP overlay path](/concepts#ivnp-backed-overlay-networking) when available; defaults to `false` |
| `ttl` | `number` | no | Requested seconds; non-positive values use 120, maximum 600. Larger values return HTTP 400. |
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
| `hostname` | `string` | friendly hostname; empty when a client that allows canonical fallback finds the friendly name owned by another identity |
| `canonical_hostname` | `string` | relay-derived identity-bound hostname used by the SDK |
| `expires_at` | `string` | lease expiry |
| `access_token` | `string` | token for renew, unregister, signer access, and direct datagram backhaul |
| `reverse_endpoint` | `ReverseEndpoint` | URL, opaque reverse-only capability, and expiry for `/sdk/connect` |
| `udp_addr`, `tcp_addr` | `string` | omitted when transport is disabled |
| `udp_enabled`, `tcp_enabled` | `boolean` | active transport flags |

The SDK uses the returned `canonical_hostname`; it does not derive or accept a
client-supplied address suffix. The canonical label ends with all 40 lowercase
hexadecimal characters of the SIWE-authenticated Ethereum address. A normalized
name of at most 22 characters precedes it with one hyphen
(`<name>-<address>`); a longer name is replaced by a 21-character hash of the
name followed by two hyphens (`<name-hash>--<address>`, derivation in the
architecture page). The current SDK allows canonical fallback.
`RelayStatus.PublicURL` reports the canonical hostname. `RelayStatus.AliasURL`
reports the returned `hostname` when the relay granted the friendly alias, and
is empty after canonical fallback or for an unnamed service. Both stay set while
the lease is held, including while reverse sessions reconnect; a failed relay
clears `AliasURL`. While the relay is ready, prefer `AliasURL` for user-facing
links and sharing, falling back to `PublicURL` when it is empty. Keep `PublicURL`
for identity-bound origins, diagnostics, and opt-in relay caching. Do not derive
the short URL by removing the address suffix: another identity may own that name.
A protocol-10 client that omits the capability receives `hostname_conflict`
instead of a canonical-only registration when its friendly hostname is already
owned by another identity.

`ReverseEndpoint`:

| Field | Type | Notes |
|-------|------|-------|
| `url` | `string` | HTTPS `/sdk/connect` endpoint on the ingress relay or its selected gateway |
| `capability` | `string` | opaque, reverse-only, and bound to this lease instance |
| `expires_at` | `string` | never later than the owning lease expiry |
| `overlay` | `boolean` | `true` when the selected endpoint uses the overlay |
| `gateway` | `RelayDescriptor` | signed descriptor binding the overlay gateway's HTTPS address to its relay identity; required when `overlay` is `true` |

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
For overlay endpoints, the SDK verifies the signed gateway descriptor and
checks that its address matches the returned URL before opening any connection.
Relay-selected gateways may only resolve to public IP addresses; local, private,
and special-purpose addresses are blocked after DNS resolution on every dial.
An explicitly configured direct relay retains local development support.
Browser/WASM clients reject relay-selected alternate gateways because the browser
does not expose resolved addresses for SDK verification. Keep `overlay` disabled
and use the explicitly configured direct relay in browser applications.

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
| `repins_chain` | `boolean` | no |

Renewal uses the same 120-second default and 600-second maximum as registration.
A rejected TTL leaves the existing lease unchanged.

`repins_chain` says the SDK re-pins the relay certificate chain by itself. A
renewal without it is answered with `lease_not_found` and the lease is not
extended when the relay now serves a certificate that the chain pinned at
registration does not verify (a renewal by another intermediate); the SDK then
registers again and pins the current chain. An SDK that only exposes raw TCP or
UDP is asked as well, although it never signs, so it reconnects once after such
a renewal. On a relay with more of these tenants than its pre-auth registration
budget admits per renewal cycle, some registrations are answered with 429 and
wait for their retry time.

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

### Waiting for approval

A relay reports its routing decision only as the answer to a reverse connect.
`RegisterResponse` and `RenewResponse` carry no approval field.

| Reverse connect answers | Meaning | `RelayStatus` |
|-------------------------|---------|---------------|
| `101` | lease may route | `State` is `ready`, `Approval` is empty |
| `403 lease_rejected` | not approved yet, or approval was revoked | `State` is `connecting`, `Approval` is `pending` |
| `403 lease_denied` | denied or banned | `State` is `connecting`, `Approval` is `refused` |

The SDK retries every 3 seconds, so an approved lease becomes ready without a
new registration. When a lease stops being routable, the relay closes its idle
reverse streams, and the lease leaves `ready` at once.

While `Approval` is set, `PublicURL`, `AliasURL`, `TCPAddr`, and `UDPAddr` are
empty and `Active()` is false, because nothing routes. The lease still exists on
the relay and renews normally.

An empty `Approval` means that no refusal was reported. It never means approved.
Show `Approval.Message()` to people: `waiting for relay approval` or
`refused by relay`.

| SDK and relay | While waiting | After a revoke |
|---------------|---------------|----------------|
| Old SDK, new relay | `connecting` | leaves `ready` for `connecting` |
| New SDK, old relay | `pending`, also when denied | stays `ready`; an old relay does not report it |
| New SDK, new relay | `pending` or `refused` | `pending` or `refused` |

The browser SDK stays at `connecting`, because a failed WebSocket does not
expose its status.

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

The maintained connector's `portalTunnel.start(options)` resolves to an object
with `publicURL` (the identity-bound canonical URL, preserving the existing
contract) and `aliasURL` (the granted short URL, or an empty string when no alias
was granted). Consumers can explicitly choose `aliasURL || publicURL` for sharing.
Consumers of older connector artifacts should treat a missing `aliasURL` the
same as an empty value.

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

## Go Application Auth

The tables above are the wire protocol. A Go program that embeds the SDK can also
put the sign-in gate of `portal expose --auth` in front of its own handler.
Package `github.com/gosuda/portal-tunnel/v2/sdk/appauth` is that gate. It is a
separate package so a program that does not use it, including a browser WASM
build, does not compile the OIDC and SAML dependencies.

```go
id, err := identity.LoadOrCreate("my-app", identityPath, "")
if err != nil {
	log.Fatal(err)
}
exposure, err := sdk.Expose(ctx, id, nil, sdk.WithDiscovery(3))
if err != nil {
	log.Fatal(err)
}
defer exposure.Close()

cfg := appauth.Config{
	Provider:  appauth.ProviderOIDC,
	EmailList: []string{"alice@example.com", "@example.org"},
	OIDCConfig: appauth.OIDCConfig{
		OIDCIssuerURL:    "https://accounts.google.com",
		OIDCClientID:     clientID,
		OIDCClientSecret: clientSecret,
	},
}
cfg.PublicHosts = publicHosts(exposure) // see Hostnames below
gate, err := appauth.New(app, id, cfg)
if err != nil {
	log.Fatal(err) // a mistake in cfg
}
if err := appauth.Check(ctx, cfg); err != nil {
	log.Printf("sign-in provider: %v", err) // sessions still work; show this in a status
}
if err := sdk.RunHTTP(ctx, exposure, gate, ""); err != nil {
	log.Fatal(err)
}
```

The application reads the visitor from the request context, with or without
identity headers:

```go
principal, ok := appauth.PrincipalFromContext(r.Context())
```

| Name | Purpose |
|------|---------|
| `New(next, id, cfg)` | Builds the gate. It reads no network, so a provider outage cannot stop a rebuild. It returns an error for a mistake in `cfg` and for an `id` without its `TokenSecret`. |
| `Check(ctx, cfg)` | Tests the provider: the OIDC discovery document and keys, the SAML metadata, or a login at the SMTP server. It sends no mail. Run it at startup and show the result. |
| `Validate(cfg)` | Runs the config checks of `New` on a `Config` that is not being built yet. It needs no identity, and it does not ask for `PublicHosts`. |
| `Config` | The provider, the allowlist, and the provider settings. `oidc`, `saml`, and `email` refuse an empty list. **An empty list opens `siwe` to any wallet, and `credential` to any credential issued from `id`.** Secrets are plain values: read them from where your program keeps secrets. |
| `Principal` | `Provider`, `Subject`, and `Email`. `Subject` is the principal the allowlist checks: a wallet address, a credential subject, an email, or a `sub:` entry. `Email` is the address `oidc`, `saml`, or `email` vouches for, or empty. An OIDC email counts only with `email_verified`. |
| `IssueCredential`, `CredentialRedeemURL` | Create a credential and its sign-in link for the `credential` provider. |
| `ProviderTakesEmailList(provider)` | Reports whether a provider reads `Config.EmailList`. The others read `Config.Allow`. |
| `ReservedPathPrefix` | `/_portal/auth/`. The gate answers its endpoints under this prefix, so serve none of your own routes there. A later release may add endpoints. |

### Keeping sessions across a rebuild

A gate built with the same `id`, including its `TokenSecret`, accepts the sessions
of an earlier gate when these settings are also the same:

| Provider | Settings |
|----------|----------|
| `oidc` | issuer and client ID |
| `saml` | metadata source, entity ID, and subject attribute |
| `email` | SMTP server, username, and sender |
| `siwe`, `credential` | none |

The allowlist is checked again on every request, so a principal you remove loses
access at once, and a rebuild does not bring it back. A change to one of these
settings ends the sessions that the old settings made.

These do not survive a rebuild:

- A SIWE login in progress: the wallet signs again.
- The list of SAML assertions already used. An assertion still valid could be presented once more.
- Email links that were mailed and not used: the visitor asks for a new one.
- Sessions on an alias, when `PublicHosts` gives its `Since`: a new exposure holds
  the alias anew, and another identity may have held it in between. Sessions on
  `PublicURL` are not affected.

Store an identity with `identity.Marshal`, not `json.Marshal`. `json.Marshal`
leaves out the `TokenSecret`. `New` refuses an identity without one, but
`identity.Parse` of a document without one creates a random secret, and every
session then ends at the next start without an error.

To replace the application, keep one gate and swap `next` behind it. Then a
redeploy changes nothing about sign-in, and an in-progress login also survives.

### Hostnames

The gate builds a redirect from the host the visitor used, so it works on every
host. An identity provider needs a registered URI for each one: the canonical
host on each relay, and the alias if you share it. Portal has no setting for one
public base URL, because an exposure on several relays has several canonical
hosts.

`Config.PublicHosts` lists the hosts the application holds now. Set it whenever the
gate serves an exposure. The `email` provider needs it, and `New` refuses `email`
without one. With it, the gate answers `421` to a request for any other host. A
session or a sign-in on a host with a `Since` must also be newer than `Since`, so
neither carries over from an earlier hold of an alias. Credentials are not dated,
because they have to outlive a restart, so issue them for `PublicURL`. Without
`PublicHosts`, the gate believes the `Host` of a request:

```go
func publicHosts(exposure *sdk.Exposure) func() []appauth.PublicHost {
	return func() []appauth.PublicHost {
		var hosts []appauth.PublicHost
		for _, relay := range exposure.Relays() {
			hosts = append(hosts,
				appauth.PublicHost{URL: relay.PublicURL},
				appauth.PublicHost{URL: relay.AliasURL, Since: relay.AliasSince})
		}
		return hosts
	}
}
```

### What the gate cannot protect

The gate protects the handler it wraps. `portal expose` refuses these
combinations, but `New` cannot see how a program exposes itself, so a program must
not combine them:

- `sdk.WithStaticRelayCache`: the relay serves the cached site without calling your handler.
- `sdk.WithTCP` and `sdk.WithUDP`: connections and datagrams do not pass through an `http.Handler`.

A session is also tied to the origin of the application. A request with a session
cookie and an `Origin` of another origin gets `403` for a protocol upgrade and for
any method other than `GET`, `HEAD`, or `OPTIONS`. A request without `Origin`, a
request that presents a credential header, and a form post with `Origin: null`
that a browser marks with `Sec-Fetch-Site: same-origin` are not affected.
