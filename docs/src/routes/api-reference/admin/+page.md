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
| `POST` | `/api/policy/ips` | Bearer | `IPPolicyUpdate` | `{}` |

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
| `is_ip_banned` | `boolean` | observed client IP is banned |

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
| `is_banned` | `boolean` | ban or unban identity registration and renewal |
| `is_approved` | `boolean` | approve or revoke explicit approval |
| `is_denied` | `boolean` | deny or remove denial; `true` also revokes approval |
| `bps` | `number` | set bytes-per-second limit; `0` removes the limit |

Lease policy updates persist to `policy.json` and return `{}` on success.

## IP Policy

`POST /api/policy/ips` accepts:

```json
{ "ip": "203.0.113.10", "is_banned": true }
```

The IP must parse as a valid IPv4 or IPv6 address.
