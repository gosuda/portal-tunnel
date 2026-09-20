---
title: API Reference
description: Portal relay API contract, endpoint groups, auth, and shared response rules.
---

# API Reference

Portal relay exposes one control-plane API. Frontends, SDK clients, peer relays,
and operators all talk to this API, but each group has a small owned surface.
Local agent endpoints under `/agent/*` are not part of the relay API.

## JSON Envelope

Matched JSON control endpoints return this envelope:

```json
{
  "ok": true,
  "data": {}
}
```

Error responses use the same envelope with `error` instead of `data`:

```json
{
  "ok": false,
  "error": {
    "code": "unauthorized",
    "message": "unauthorized"
  }
}
```

`data` is omitted on error. `error` is omitted on success.

The envelope does not apply to streaming or delegated endpoints:

| Path | Format |
|------|--------|
| `/llms.txt` | Markdown-formatted plain-text relay and tunnel connection guide |
| `/sdk/connect` | HTTP/1.1 connection hijack |
| `/v1/sign` | keyless TLS signer protocol |
| `/api/x402/*` | relay-owned x402 facilitator response |
| `/api/install.sh`, `/api/install.ps1`, `/api/install/bin/*` | script or binary bytes |

Unknown routes may be handled by the frontend fallback or return a normal
HTTP 404 outside the envelope.

## Auth Schemes

| Name | Used by | How it is sent |
|------|---------|----------------|
| None | public and challenge endpoints | no credential |
| Admin bearer | admin API | `Authorization: Bearer <access_token>` |
| Lease token header | keyless signer and static cache | `X-Portal-Access-Token: <access_token>` |
| Reverse capability header | reverse stream | `X-Portal-Reverse-Capability: <capability>` |
| Lease token body | lease renew/reverse/unregister | JSON field `access_token` |
| Signed descriptor | relay discovery announce | signed `RelayDescriptor` body |

The QUIC datagram backhaul carries the lease access token in a JSON message
on its first stream, rather than an HTTP header. Cache endpoints can return
plain-text HTTP errors for unsupported methods or exhausted request slots.

Admin auth and SDK lease auth issue different tokens and are not
interchangeable. SDK lease registration uses SIWE; relay admin access uses the
configured admin token.

## Endpoint Groups

### Public

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/` | None | selected SPA `index.html` |
| `GET`/`HEAD` | `/llms.txt` | None | relay and tunnel connection guide |
| `GET` | `/api/healthz` | None | `{ "status": "ok" }` |
| `GET` | `/api/state` | None | `PublicStateResponse` |
| `GET`/`HEAD` | `/api/install.sh`, `/api/install.ps1` | None | install script |
| `GET`/`HEAD` | `/api/install/bin/{slug}` | None | install binary or redirect |

Detailed contracts: [SDK API](/api-reference/sdk) and
[Admin and Policy API](/api-reference/admin).

### SDK

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `GET` | `/sdk/domain` | None | none | `DomainResponse` |
| `POST` | `/sdk/register/challenge` | None | `RegisterChallengeRequest` | `RegisterChallengeResponse` |
| `POST` | `/sdk/register` | SIWE signature body | `RegisterRequest` | `RegisterResponse` |
| `POST` | `/sdk/renew` | lease token body | `RenewRequest` | `RenewResponse` |
| `POST` | `/sdk/reverse` | lease token body | `ReverseEndpointRequest` | `ReverseEndpoint` |
| `POST` | `/sdk/unregister` | lease token body | `UnregisterRequest` | `{}` |
| `GET` | `/sdk/connect` | reverse capability header | none | hijacked stream |
| `POST` | `/sdk/cache` | lease token header | `StaticCacheManifest` JSON | `StaticCacheStatus` |
| `PUT` | `/sdk/cache` | lease token header | manifest and file bytes as multipart | `StaticCacheStatus` |
| `DELETE` | `/sdk/cache` | lease token header | none | `StaticCacheStatus` |

### Admin

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `POST` | `/api/admin/auth/login` | None | `AdminAuthLoginRequest` | `AdminAuthLoginResponse` |
| `GET` | `/api/admin/auth/status` | Optional admin bearer | none | `AdminAuthStatusResponse` |
| `POST` | `/api/admin/auth/logout` | Admin bearer | none | `{}` |

`/admin` itself is a frontend route, not a relay API endpoint.

### Payments

Relay `/api/x402/*` endpoints are optional relay-owned control-plane
facilitator endpoints. Enable them with `X402_ENABLED=true` when a relay
operator wants to reserve support for relay resources such as future tunnel
registration fees, lease renewal fees, raw TCP/UDP port allocation, or premium
capacity. They are served by the embedded `gosuda/x402-facilitator` handler and
do not use the Portal JSON envelope. Portal selects Sui mainnet by default and
Sui testnet when `X402_TESTNET=true`. Portal accepts only USDC gasless
stablecoin address-balance payments. `X402_PAY_TO` is the relay-owned payment
recipient.

Relay x402 settings do not affect tunnel paid routes. Tunnel payment recipients
and payment networks are local tunnel configuration and are not part of the
relay lease API.

Paid routed HTTP tunnels additionally expose `/x402/prepare` and
`/x402/client.js` on the public tunnel origin. Those are tunnel-owned helper
endpoints for app frontends, not relay API routes, and they do not use the
`/api` prefix. `/x402/client.js` and the transaction-building prepare response
are Sui-only. Casper clients consume the protected resource's 402 requirements,
sign with an external Casper x402 SDK, and retry with `PAYMENT-SIGNATURE` or
`X-PAYMENT`; Portal then delegates verification and settlement to the configured
Casper facilitator.

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `GET` | `/api/x402/supported` | None | none | x402 supported kinds |
| `POST` | `/api/x402/verify` | None | x402 verify request | x402 verify response |
| `POST` | `/api/x402/settle` | None | x402 settle request | x402 settle response |

### Policy

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `GET` | `/api/policy` | Admin bearer | none | `PolicySettings` |
| `POST` | `/api/policy` | Admin bearer | `PolicySettings` | `PolicySettings` |
| `GET` | `/api/policy/state` | Admin bearer | none | `PolicyStateResponse` |
| `POST` | `/api/policy/leases` | Admin bearer | `LeasePolicyUpdate` | `{}` |

### Relay

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/discovery` | None | `DiscoveryResponse` |
| `POST` | `/discovery/announce` | Signed descriptor | `DiscoveryAnnounceResponse` |
| `POST` | `/v1/sign` | Lease token header | keyless signer response |

## Shared Types

Timestamps are JSON-encoded Go `time.Time` values.

`Identity`:

| Field | Type | Notes |
|-------|------|-------|
| `name` | `string` | DNS label used by the lease |
| `address` | `string` | Ethereum address |

`LeaseMetadata`:

| Field | Type | Notes |
|-------|------|-------|
| `description` | `string` | optional |
| `owner` | `string` | optional |
| `thumbnail` | `string` | optional URL or data value |
| `tags` | `string[]` | optional |
| `hide` | `boolean` | hidden leases are omitted from the public state |

`Lease`:

| Field | Type |
|-------|------|
| `name` | `string` |
| `expires_at`, `first_seen_at`, `last_seen_at` | `string` |
| `hostname` | `string` |
| `udp_enabled`, `tcp_enabled` | `boolean` |
| `tcp_addr` | `string` |
| `metadata` | `LeaseMetadata` |
| `ready` | `number` |

`PolicyLease` extends `Lease` with:

| Field | Type |
|-------|------|
| `identity_key`, `address` | `string` |
| `bps` | `number` |
| `client_ip`, `reported_ip` | `string` |
| `is_approved`, `is_banned`, `is_denied` | `boolean` |

`PublicStateResponse`:

| Field | Type |
|-------|------|
| `leases` | `Lease[]` |
| `landing_page_enabled` | `boolean` |

`PolicyStateResponse`:

| Field | Type |
|-------|------|
| `policy` | `PolicySettings` |
| `leases` | `PolicyLease[]` |

`PolicyPortSettings`:

| Field | Type | Notes |
|-------|------|-------|
| `enabled` | `boolean` | enables the transport |
| `max_leases` | `number` | `0` means unlimited |

`PolicySettings`:

| Field | Type |
|-------|------|
| `approval_mode` | `"auto"` or `"manual"` |
| `landing_page_enabled` | `boolean` |
| `udp` | `PolicyPortSettings` |
| `tcp_port` | `PolicyPortSettings` |

`LeasePolicyUpdate`:

| Field | Type | Notes |
|-------|------|-------|
| `identity_key` | `string` | normalized `name:address` key |
| `is_banned` | `boolean` | optional |
| `is_approved` | `boolean` | optional |
| `is_denied` | `boolean` | optional; `true` also revokes approval |
| `bps` | `number` | optional; `0` removes the limit |

`DiscoveryResponse`:

| Field | Type | Notes |
|-------|------|-------|
| `protocol_version` | `string` | discovery protocol version of the serving relay |
| `generated_at` | `string` | when the response was generated |
| `relays` | `RelayDescriptor[]` | signed, routable relay descriptors |
| `incompatible_relays` | `IncompatibleRelayEntry[]` | optional; relays contacted directly whose discovery protocol version differs |
| `release_version` | `string` | optional; release of the serving relay itself |
| `relay_observations` | `RelayObservation[]` | optional; release observations about peer relays it contacted directly |

`RelayObservation`:

| Field | Type | Notes |
|-------|------|-------|
| `url` | `string` | API URL of the peer relay the serving relay contacted directly |
| `release_version` | `string` | optional; release observed from that relay's own `/discovery` response |
| `last_seen_at` | `string` | when the serving relay last contacted it |

`release_version` and `relay_observations` are optional, unsigned observation metadata: they never affect routing, trust, signature verification, or compatibility, and older relays omit them. Signed relay identity stays in `RelayDescriptor`.

## Common Errors

| Code | Meaning |
|------|---------|
| `invalid_json` | request body is not valid JSON |
| `invalid_request` | request shape or value is invalid |
| `method_not_allowed` | endpoint does not accept the method |
| `unauthorized` | credential is missing, expired, or invalid |
| `feature_unavailable` | feature is disabled or not configured |
| `rate_limited` | request was throttled |
| `hostname_conflict` | lease hostname is already registered |
| `lease_not_found` | lease token or identity has no active lease |
| `lease_rejected` | lease is not currently allowed to route |
| `invalid_address` | address path or body value is invalid |
| `invalid_mode` | approval mode is not `auto` or `manual` |
| `http11_only` | endpoint requires HTTP/1.1 |
| `hijack_unsupported`, `hijack_failed` | reverse stream setup failed |
| `udp_disabled`, `udp_capacity_exceeded`, `udp_port_exhausted` | UDP lease cannot be allocated |
| `tcp_port_disabled`, `tcp_port_capacity_exceeded`, `tcp_port_exhausted` | TCP port lease cannot be allocated |
| `transport_mismatch` | request does not match the active lease transport |
| `internal` | unexpected server failure |
