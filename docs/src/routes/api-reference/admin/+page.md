---
title: Admin And Policy API
description: Portal relay operator endpoints for auth and policy control.
---

# Admin And Policy API

Operator endpoints are the control surface for a relay. They all return
the standard JSON envelope described in [API Reference](/api-reference), except
for internal operational endpoints that are not part of the stable API.

`/admin` is reserved for the frontend route. Relay admin auth endpoints live
under `/api/admin`, and enforcement settings live under `/api/policy`.

## Auth Flow

1. Set `ADMIN_TOKEN` on the relay.
2. `POST /api/admin/auth/login` with `{ "token": "<admin-token>" }`.
3. Send the returned `access_token` as `Authorization: Bearer <token>`.
4. `POST /api/admin/auth/logout` to clear the browser-stored token.

Admin bearer tokens are separate from SDK lease tokens.

## Endpoints

| Method | Path | Auth | Body | Data |
|--------|------|------|------|------|
| `POST` | `/api/admin/auth/login` | None | `AdminAuthLoginRequest` | `AdminAuthLoginResponse` |
| `GET` | `/api/admin/auth/status` | Optional bearer | none | `AdminAuthStatusResponse` |
| `POST` | `/api/admin/auth/logout` | Bearer | none | `{}` |
| `GET` | `/api/policy` | Bearer | none | `PolicySettings` |
| `POST` | `/api/policy` | Bearer | `PolicySettings` | `PolicySettings` |
| `GET` | `/api/policy/state` | Bearer | none | `PolicyStateResponse` |
| `POST` | `/api/policy/leases` | Bearer | `LeasePolicyUpdate` | `{}` |
| `GET` | `/api/admin/metrics` | Bearer | none | Prometheus text exposition |

## Relay Metrics

`GET /api/admin/metrics` uses the same `ADMIN_TOKEN` bearer check as the other
admin endpoints. Configure the scraper with a bearer token and restrict access
to this operator route. When `ADMIN_TOKEN` is unset, the endpoint cannot be
scraped. The relay uses the standard Prometheus handler on this existing route;
there is no separate metrics listener or exporter setting, and no public
`/metrics` endpoint.

| Metric | Type | Meaning |
|--------|------|---------|
| `portal_relay_active_leases` | gauge | Non-expired lease registrations; one lease counts once even if it enables both TCP and UDP. |
| `portal_relay_active_connections` | gauge | Bridged HTTP/SNI and raw TCP streams, including overlay streams. |
| `portal_relay_active_udp_flows` | gauge | Tracked flows on active leases, including idle flows until expiry. |
| `portal_relay_forwarded_stream_bytes_total` | counter | Successful stream bytes written in both directions; excludes UDP payloads. |
| `portal_relay_http_requests_total{method,code}` | counter | Requests through the relay HTTP handler; methods outside the standard set use `unknown`. |
| `portal_relay_http_request_duration_seconds{code}` | histogram | Time spent in the relay HTTP handler, in seconds. |

The HTTP series include control API and frontend requests, but not SNI-routed
tenant streams or raw TCP/UDP traffic. They have no URL, host, tenant, or
application labels. The snapshot series read `portal.Server.Stats()` during
each scrape and can reflect concurrent changes between fields. The forwarded
byte counter resets with a new Server instance; HTTP counters reset with a new
relay metrics registry. Standard Go and process metrics are included.
The current snapshot cannot provide separate HTTP/SNI, raw TCP, and UDP traffic
panels; that requires a separate relay stats contract change.

## Auth Payloads

`AdminAuthLoginRequest`:

| Field | Type | Required |
|-------|------|----------|
| `token` | `string` | yes |

`AdminAuthLoginResponse`:

| Field | Type |
|-------|------|
| `access_token` | `string` |

`AdminAuthStatusResponse`:

| Field | Type | Notes |
|-------|------|-------|
| `authenticated` | `boolean` | true only when a valid bearer token was sent |

## State

`GET /api/policy/state` returns the full policy view:

| Field | Type |
|-------|------|
| `policy` | `PolicySettings` |
| `leases` | `PolicyLease[]` |

`PolicyLease` uses the shared `Lease` fields from [API Reference](/api-reference#shared-types)
and adds:

| Field | Type | Notes |
|-------|------|-------|
| `identity_key` | `string` | normalized `name:address` key |
| `address` | `string` | normalized Ethereum address |
| `bps` | `number` | bytes per second limit, `0` means unlimited |
| `client_ip` | `string` | relay-observed client IP |
| `reported_ip` | `string` | client-reported public IP, when present |
| `is_approved` | `boolean` | effective approval result |
| `is_banned` | `boolean` | identity is banned |
| `is_denied` | `boolean` | identity is denied |

## Policy

Policy settings are written as one object through `POST /api/policy` and returned
in the same shape:

```json
{
  "approval_mode": "manual",
  "landing_page_enabled": false,
  "udp": {
    "enabled": true,
    "max_leases": 10
  },
  "tcp_port": {
    "enabled": false,
    "max_leases": 0
  }
}
```

`max_leases` must be non-negative. `0` means unlimited.

Supported modes:

| Mode | Behavior |
|------|----------|
| `auto` | active leases can route unless banned or denied |
| `manual` | active leases route only after approval |

## Lease Policy

`POST /api/policy/leases` accepts a partial policy update for one identity:

| Field | Type | Effect |
|-------|------|--------|
| `identity_key` | `string` | normalized `name:address` key |
| `is_banned` | `boolean` | block or unblock routing for the identity |
| `is_approved` | `boolean` | approve or revoke explicit approval |
| `is_denied` | `boolean` | deny or remove denial; `true` also revokes approval |
| `bps` | `number` | set bytes-per-second limit; `0` removes the limit |

Lease policy updates persist to `policy.json` and return `{}` on success.
